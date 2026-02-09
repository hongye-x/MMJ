package main

/*
#cgo LDFLAGS:
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"net/rpc"
	"os"

	"net"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	i "sig_vfy/src/initialize"
	"sig_vfy/src/keymanage"
	slog "sig_vfy/src/log"
	"sig_vfy/src/sqlop"
	w "sig_vfy/src/whitetable"
	"sync"
	"unsafe"
)

var s_m_sockname = "/tmp/Ser_Man.sock"

var RWmu sync.RWMutex

var CrySerStatus b.ServerStatus
var SM2KeyCanUseList = make(map[net.Conn][]byte)
var RSAKeyCanUseList = make(map[net.Conn][]byte)
var CSDevH unsafe.Pointer
var CSSesH unsafe.Pointer
var CRootKey []byte
var CSSymMap map[int]*keymanage.MemStorSymKey
var CSSm2Map map[int]*keymanage.MemStorSM2Key
var CSRsaMap map[int]*keymanage.MemStorRSAKey
var Server_IP string

var RandFile = "./random_data.bin"
var UserCserver int = 128 // 密码运算服务用户type
var UserCserverUUID = []byte("Crypto_server")

func csinit() *b.StdErr {
	list, stderr := b.ReadConfigValues("CRYPTO_SERVER_IP", "CRYPTO_SERVER_PORT", "CRYPTO_SERVER_LOG_ASYNC")
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
		slog.CServerLogWrite(slog.Error, "127.0.0.1",
			"Crypto Server Start --> SDF OpenDev Func Error Code[%08X]", iret)
		os.Exit(1)
	} else {
		sesh, iret := ISDF.OpenSession(devh)
		if iret != 0 {
			slog.CServerLogWrite(slog.Error, "127.0.0.1",
				"Crypto Server Start --> SDF OpenSes Func Error Code[%08X]", iret)
			os.Exit(1)
		} else {
			CSDevH = devh
			CSSesH = sesh
		}
	}
	iret = ISDF.Sudo(CSSesH)
	if iret != 0 {
		slog.CServerLogWrite(slog.Error, "127.0.0.1",
			"Crypto Server Start --> SDF GetRight Func Error Code[%08X]", iret)
		os.Exit(1)
	}

	CSSymMap = keymanage.MemSymMap
	CSSm2Map = keymanage.MemSM2Map
	CSRsaMap = keymanage.MemRSAMap

	CrySerStatus.ConnNums = 0
	CrySerStatus.CpuOcc = 0
	CrySerStatus.MemOcc = 0
	CrySerStatus.OnBoot = 0

	ip := list["CRYPTO_SERVER_IP"].([]byte)
	port := list["CRYPTO_SERVER_PORT"].(int)
	Server_IP = fmt.Sprintf("%s:%d", ip, port)

	// 注册和管理端的rpc接口
	err := rpcRegister()
	if err != nil {
		fmt.Println("Rpc Register Error Code[%08X]", b.RPC_REGORCALL_ERROR)
		os.Exit(1)
	}

	return nil
}

func csclean() {
	if CSSesH != nil {
		ISDF.CloseSession(CSSesH)
	}
	if CSDevH != nil {
		ISDF.CloseDevice(CSDevH)
	}
	slog.LogDeInit()
}

func parsClientMsgAndSend(conn net.Conn) *b.StdErr {
	stderr := ParsClientMsgAndSend_SVS(conn)
	if stderr != nil {
		if stderr.Errcode == b.ASN1TYPE_ERROR {
			ParsClientMsgAndSend_MMJ(conn)
		}
	}
	return nil
}

func server4client(wg *sync.WaitGroup) {
	defer wg.Done()

	// 软件完整性校验

	// 算法正确性自检
	var cryptoCheckFlag byte = i.SM1_TEST_FLAG | i.SM2_SE_TEST_FLAG | i.SM3_TEST_FLAG | i.SM4_TEST_FLAG
	stderr := i.AlgCorrectnessCheck(CSSesH, cryptoCheckFlag)
	if stderr != nil {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> Alg Correctness Check Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		return
	}

	// 随机数质量检测
	// fmt.Println("Waiting For Random Dectection...")
	// _, stderr = i.RandomPowerOnDetection(RandFile)
	// if stderr != nil {
	// 	b.PrintStdErr(stderr)
	// 	return
	// }

	// 检查设备是否初始化
	if keymanage.GetDevInitStatus() == 0 {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> Device Has Not Been Initialized")
		fmt.Println("The Device Has Not Been Initialized Yet")
		return
	}

	// 获取主密钥
	stderr = i.GetRootKey(CSSesH)
	if stderr != nil {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> Root Key Not Exist Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}
	CRootKey = i.PRootKey

	// 密钥完整性自检
	stderr = i.KeyLoad(CSSesH, CRootKey)
	if stderr != nil {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> Key Integrity Check Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}

	stderr = i.CAInfoLoad()
	if stderr != nil {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> CA Info Load Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}

	stderr = i.AppInfoLoad()
	if stderr != nil {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> App Info Load Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}

	stderr = i.CACertInfoLoad()
	if stderr != nil {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> CA Cert Info Load Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}

	stderr = i.AppCertInfoLoad()
	if stderr != nil {
		slog.CServerLogWrite(slog.Error, Server_IP,
			"Crypto Server Start --> App Cert Info Load Error Code[%08X]", stderr.Errcode)
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}

	// 加载白名单
	stderr = w.AddCIDR2IPNets("127.0.0.1")
	if stderr != nil {
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}
	stderr = w.LoadIPNetsFromDB()
	if stderr != nil {
		b.PrintStdErr(stderr)
		os.Exit(-1)
	}

	// testcsr()

	ln, err := net.Listen("tcp", Server_IP)
	if err != nil {
		slog.CServerLogWrite(slog.Error, "127.0.0.1",
			"Crypto Server Start --> Listen Error")
		fmt.Println(err)
		os.Exit(-1)
	}
	defer ln.Close()

	fmt.Println("Waiting For Connection")
	for {
		conn, err := ln.Accept()
		if err != nil {
			conn.Close()
			continue
		} else {
			connip, stderrtmp := w.GetClientIP(conn)
			if stderrtmp != nil {
				slog.CServerLogWrite(slog.Warning, conn.RemoteAddr().String(),
					"Crypto Server Listen --> Unknow IP Type")
				b.PrintStdErr(stderrtmp)
				conn.Close()
				continue
			} else {
				accept := w.CheckIPFromIPNets(connip)
				if accept == 0 {
					slog.CServerLogWrite(slog.Warning, conn.RemoteAddr().String(),
						"Crypto Server Listen --> Access Denied IP : [%s]", conn.RemoteAddr().String())
					b.PrintStdErr(b.CreateStdErr(b.ACCESS_DENIED, "Access Denied IP : [%s]", connip))
					conn.Close()
					continue
				}
			}
			if CrySerStatus.ConnNums >= b.MAX_CONNECTION {
				slog.CServerLogWrite(slog.Warning, conn.RemoteAddr().String(),
					"Crypto Server Listen --> Connection Exceed Limit Code[%08X]", b.OUTOF_MAX_CONNECTION)
				rtmsg := make([]byte, 8)
				binary.BigEndian.PutUint32(rtmsg, uint32(8))
				binary.BigEndian.PutUint32(rtmsg[4:], uint32(b.OUTOF_MAX_CONNECTION))
				conn.Write(rtmsg)
				conn.Close()
				continue
			}
			RWmu.Lock()
			CrySerStatus.ConnNums++
			SM2KeyCanUseList[conn] = make([]byte, b.MAX_SM2_KEY_NUM)
			RSAKeyCanUseList[conn] = make([]byte, b.MAX_RSA_KEY_NUM)
			RWmu.Unlock()
			go parsClientMsgAndSend(conn)
		}
	}
}

func server4manage(wg *sync.WaitGroup) {
	defer wg.Done()

	os.Remove(s_m_sockname)

	ln, err := net.Listen("unix", s_m_sockname)
	if err != nil {
		slog.CServerLogWrite(slog.Warning, Server_IP,
			"Crypto Server For Manage Start --> Listen Error")
		fmt.Println("Error starting the server:", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go rpc.ServeConn(conn)
	}
}

func main() {
	csinit()
	defer csclean()
	//detect

	var wg sync.WaitGroup
	wg.Add(1)
	go server4client(&wg)
	wg.Add(1)
	go server4manage(&wg)
	wg.Wait()
}
