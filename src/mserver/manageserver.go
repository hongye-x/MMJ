package main

/*
#cgo LDFLAGS:
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/rpc"
	"os"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	i "sig_vfy/src/initialize"
	"sig_vfy/src/keymanage"
	slog "sig_vfy/src/log"
	ISV "sig_vfy/src/sigvfy"
	"sig_vfy/src/sqlop"
	"sync"
	"unsafe"
)

var s_m_sockname = "/tmp/Ser_Man.sock"

var ( // Cserver的域套接字
	cryptoClient *rpc.Client
	clientMu     sync.Mutex
)

var RWmu sync.RWMutex
var UserMserver int = 127 // 管理服务用户type
var UserMserverUUID = []byte("Manage_server")

type ManageServerStatus struct {
	OnBoot   int // 开机自启
	ConnNums int // 连接数
	CpuOcc   int //	cpu占用率
	MemOcc   int // 内存占用率
}

var ManSerStatus ManageServerStatus
var MSDevH unsafe.Pointer
var MSSesH unsafe.Pointer
var MRootKey []byte

var Server_IP string

var MSCAMap map[string]*ISV.MemoryCAInfo // 内部CA信息结构

var MDevInitedFlag = 0

func msinit() *b.StdErr {
	list, stderr := b.ReadConfigValues("MANAGE_SERVER_IP", "MANAGE_SERVER_PORT", "CRYPTO_SERVER_LOG_ASYNC")
	if stderr != nil {
		return stderr
	}
	asyncflag := list["CRYPTO_SERVER_LOG_ASYNC"].(int)
	slog.LogInit(asyncflag)

	stderr = sqlop.SqlCreate()
	if stderr != nil {
		os.Exit(1)
	}

	stderr = sqlop.SqlConnect()
	if stderr != nil {
		os.Exit(1)
	}

	devh, iret := ISDF.OpenDevice()
	if iret != 0 {
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"SDF OpenDev Func Error Code[%08X]", iret)
		os.Exit(1)
	} else {
		sesh, iret := ISDF.OpenSession(devh)
		if iret != 0 {
			slog.MServerLogWrite(slog.Error,
				UserMserver, UserMserverUUID,
				"SDF OpenSes Func Error Code[%08X]", iret)
			os.Exit(1)
		} else {
			MSDevH = devh
			MSSesH = sesh
		}
	}

	iret = ISDF.Sudo(MSSesH)
	if iret != 0 {
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"SDF GetRight Func Error Code[%08X]", iret)
		os.Exit(1)
	}

	MSCAMap = ISV.GCaInfo

	ManSerStatus.ConnNums = 0
	ManSerStatus.CpuOcc = 0
	ManSerStatus.MemOcc = 0
	ManSerStatus.OnBoot = 0

	ip := list["MANAGE_SERVER_IP"].([]byte)
	port := list["MANAGE_SERVER_PORT"].(int)
	Server_IP = fmt.Sprintf("%s:%d", ip, port)

	return nil
}

func msclean() {
	if MSDevH != nil {
		ISDF.CloseSession(MSDevH)
	}
	if MSSesH != nil {
		ISDF.CloseDevice(MSSesH)
	}
	slog.LogDeInit()
}

func getRPCClient() (*rpc.Client, error) {
	clientMu.Lock()
	defer clientMu.Unlock()

	// 如果已有客户端，检查是否健康
	if cryptoClient != nil {
		var dummy int
		err := cryptoClient.Call("Ping.Ping", &struct{}{}, &dummy)
		if err == nil {
			return cryptoClient, nil
		}
		// 连接失效，清理
		cryptoClient.Close()
		cryptoClient = nil
	}

	// 创建新连接
	conn, err := net.Dial("unix", s_m_sockname)
	if err != nil {
		return nil, err
	}

	cryptoClient = rpc.NewClient(conn)
	return cryptoClient, nil
}

func main() {
	msinit()
	defer msclean()

	go getRPCClient()

	// 软件完整性校验

	// 算法正确性自检
	var cryptoCheckFlag byte = i.SM1_TEST_FLAG | i.SM2_SE_TEST_FLAG | i.SM3_TEST_FLAG | i.SM4_TEST_FLAG
	stderr := i.AlgCorrectnessCheck(MSSesH, cryptoCheckFlag)
	if stderr != nil {
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"Alg Correctness Check Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		return
	}

	// 检查设备是否初始化
	MDevInitedFlag = keymanage.GetDevInitStatus()

	// 获取主密钥
	if MDevInitedFlag == 1 {
		stderr = i.GetRootKey(MSSesH)
		if stderr != nil {
			slog.MServerLogWrite(slog.Error,
				UserMserver, UserMserverUUID,
				"Get Server Root Key Error Code[%08X]", stderr.Errcode)
			b.PrintStdErr(stderr)
			os.Exit(1)
		}
		MRootKey = i.PRootKey
	}

	stderr = i.CAInfoLoad()
	if stderr != nil {
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"Load CA Info Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		return
	}

	stderr = i.AppInfoLoad()
	if stderr != nil {
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"Load App Info Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		return
	}

	stderr = i.AppCertInfoLoad()
	if stderr != nil {
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"Load Cert Info Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		return
	}

	stderr = i.CACertInfoLoad()
	if stderr != nil {
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"Load Cert Info Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		return
	}

	// testcreate()
	// waiting for msg
	ln, err := net.Listen("tcp", Server_IP)
	if err != nil {
		fmt.Println(err)
		slog.MServerLogWrite(slog.Error,
			UserMserver, UserMserverUUID,
			"Server Listen Error")
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("Waiting For Connection")
	for {
		conn, err := ln.Accept()
		if err != nil {
			conn.Close()
			continue
		} else {
			if ManSerStatus.ConnNums >= b.MAX_CONNECTION {
				rtmsg := make([]byte, 8)
				binary.BigEndian.PutUint32(rtmsg, uint32(8))
				binary.BigEndian.PutUint32(rtmsg[4:], uint32(b.OUTOF_MAX_CONNECTION))
				conn.Write(rtmsg)
				conn.Close()
				continue
			}
			RWmu.Lock()
			ManSerStatus.ConnNums++
			RWmu.Unlock()
			go ParsMsgAndSend(conn)
		}
	}
}

// func testcreate() {
// 	var cif ISV.MemoryCAInfo
// 	cif.Name = []byte("testCA")
// 	cif.IP = []byte("1.1.1.1:12312")
// 	cif.Status = 0

// 	cif.DefaultCRL = []byte("")
// 	cif.DefaultOCSP = []byte("")
// 	stderr := ISV.UpdateCaInfo2Sql(&cif, nil)
// 	if stderr != nil {
// 		slog.MServerLogWrite(slog.Error,
// 			UserMserver, UserMserverUUID,
// 			"Update CA Info Error Code[%08X]", stderr.Errcode)
// 		b.PrintStdErr(stderr)
// 		return
// 	}

// 	var cifcert ISV.MemoryCACertInfo
// 	cifcert.BelongCAName = cif.Name
// 	cacrt, _ := os.ReadFile("../test/certtest/ca.crt")
// 	cacertder, _ := pem.Decode(cacrt)
// 	x509c, err := ISV.ParseCert2_x509(cacertder.Bytes)
// 	cifcert.CertPem = cacrt
// 	cifcert.CertSerial = x509c.SerialNumber.Bytes()

// 	stderr = ISV.UpdatCACertInfo2Sql(&cifcert)
// 	if stderr != nil {
// 		slog.MServerLogWrite(slog.Error,
// 			UserMserver, UserMserverUUID,
// 			"Update CACert Info Error Code[%08X]", stderr.Errcode)
// 		b.PrintStdErr(stderr)
// 		return
// 	}

// 	var apif ISV.MemoryAPPInfo
// 	apif.Name = []byte("testApp")
// 	apif.IP = []byte("1.1.1.2:123")
// 	apif.CAName = []byte("testCA")
// 	apif.Status = 0
// 	stderr = ISV.UpdateAppInfo2Sql(&apif, nil)
// 	if stderr != nil {
// 		slog.MServerLogWrite(slog.Error,
// 			UserMserver, UserMserverUUID,
// 			"Update App Info Error Code[%08X]", stderr.Errcode)
// 		b.PrintStdErr(stderr)
// 		return
// 	}

// 	var crtif ISV.MemoryAppCertInfo
// 	crtif.BelongKeyType = 0
// 	crtif.BelongKeyIdx = 1
// 	crtif.BelongKeySV = 0
// 	crtif.BelongAppName = apif.Name
// 	crtif.BelongCAName = apif.CAName
// 	usercrt, _ := os.ReadFile("../test/certtest/user_enc.crt")
// 	usercertder, _ := pem.Decode(usercrt)
// 	x509u, err := ISV.ParseCert2_x509(usercertder.Bytes)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	crtif.CertPem = usercrt
// 	crtif.CertSerial = x509u.SerialNumber.Bytes()

// 	stderr = ISV.UpdateAppCertInfo2Sql(&crtif)
// 	if stderr != nil {
// 		slog.MServerLogWrite(slog.Error,
// 			UserMserver, UserMserverUUID,
// 			"Update Cert Info Error Code[%08X]", stderr.Errcode)
// 		b.PrintStdErr(stderr)
// 		return
// 	}

// 	stderr = ISV.ReLoadCaInfoFromSql(cif.Name)
// 	if stderr != nil {
// 		slog.MServerLogWrite(slog.Error,
// 			UserMserver, UserMserverUUID,
// 			"Reload CA Info Error Code[%08X]", stderr.Errcode)
// 		b.PrintStdErr(stderr)
// 		return
// 	}

// 	stderr = ISV.ReloadAppInfoFromSql(apif.Name)
// 	if stderr != nil {
// 		slog.MServerLogWrite(slog.Error,
// 			UserMserver, UserMserverUUID,
// 			"Reload App Info Error Code[%08X]", stderr.Errcode)
// 		b.PrintStdErr(stderr)
// 		return
// 	}

// 	stderr = ISV.ReloadAppCertInfoFromSql(crtif.CertSerial)
// 	if stderr != nil {
// 		slog.MServerLogWrite(slog.Error,
// 			UserMserver, UserMserverUUID,
// 			"Reload Cert Info Error Code[%08X]", stderr.Errcode)
// 		b.PrintStdErr(stderr)
// 		return
// 	}

// }
