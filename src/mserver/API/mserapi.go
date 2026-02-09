package msAPI

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// 连接管理服务失败
const CON2MS int = 0x000F2001

// 消息发送失败
const SEND2MS int = 0x000F2002

// 消息接收失败
const RECVFROMMS int = 0x000F2003

const SYM_TYPE_FLAG int = 0

var gconn net.Conn = nil

type ECCrefPublicKey struct {
	Bits uint
	X    [64]byte
	Y    [64]byte
}

type DeviceInof struct {
	IssuerName      [40]byte // 设备生产厂商名称
	DeviceName      [16]byte // 设备型号
	DeviceSerial    [16]byte // 设备编号
	DeviceVersion   uint     // 密码设备内部软件版本号
	StandardVersion uint     // 密码设备支持的接口规范版本号
	AsymAlgAbility  [2]uint  // （非对称算法）前四字节表示支持的算法；后四字节表示算法的最大模长
	SymAlgAbility   uint     // （对称算法）所有支持的对称算法
	HashAlgAbility  uint     // 所有支持的杂凑算法
	BufferSize      uint     // 支持的最大文件存储空间
}

type SysInfo struct {
	UpTime      uint // 启动时长
	CpuUsage    uint // CPU占用情况
	MemoryUsage uint // 内存占用情况
}

// InterfaceInfo 网络接口信息
type IPV4_InterfaceInfo struct {
	Name     [16]byte // 接口名称
	IP       [4]byte  // IP地址
	Gateway  [4]byte  // 网关地址
	Netmask  [4]byte  // 子网掩码
	IsActive int      // 网卡是否活跃
}

func readConfigValues(keys ...string) map[string]interface{} {
	const CONFFILE_PATH = "./config.conf"

	file, err := os.Open(CONFFILE_PATH)
	if err != nil {
		return nil
	}
	defer file.Close()

	results := make(map[string]interface{})
	for _, key := range keys {
		results[key] = nil
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		for _, key := range keys {
			if strings.HasPrefix(line, key) {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					valueStr := strings.TrimSpace(parts[1])

					if intValue, err := strconv.Atoi(valueStr); err == nil {
						results[key] = intValue
					} else {
						results[key] = []byte(valueStr)
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil
	}

	return results
}

func Connect2ManageServer(address string) int {
	conn1, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error Connecting To Server:", err)
		return CON2MS
	}
	gconn = conn1
	return 0
}

func init() {
	list := readConfigValues("MANAGE_SERVER_IP", "MANAGE_SERVER_PORT")
	if list == nil {
		os.Exit(3)
	}
	ip := list["MANAGE_SERVER_IP"].([]byte)
	port := list["MANAGE_SERVER_PORT"].(int)
	address := fmt.Sprintf("%s:%d", ip, port)
	iret := Connect2ManageServer(address)
	if iret != 0 {
		os.Exit(iret)
	}
}

// 0:sig	1:enc
func Manage_GenKey(user_type int, user_name_or_uuid []byte,
	keytype int, keyidx int, sigORenc int, keybits int, pswd []byte) int {
	var msgLen = 44 + 4 + 4 + 4 + len(pswd)
	var cmd = 0xB001
	var msg = make([]byte, msgLen)

	if keytype != SYM_TYPE_FLAG {
		if sigORenc == 0 {
			keyidx = keyidx*2 - 1
		} else if sigORenc == 1 {
			keyidx = keyidx * 2
		}
	}
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	binary.BigEndian.PutUint32(msg[offset:], uint32(keytype))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(keybits))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(keyidx))
	offset += 4
	copy(msg[offset:], pswd)

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_DelKey(user_type int, user_name_or_uuid []byte, keytype int, keyidx int, sigORenc int) int {
	var msgLen = 44 + 4 + 4
	var cmd = 0xB002
	var msg = make([]byte, msgLen)

	if keytype != SYM_TYPE_FLAG {
		if sigORenc == 0 {
			keyidx = keyidx*2 - 1
		} else if sigORenc == 1 {
			keyidx = keyidx * 2
		}
	}
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	binary.BigEndian.PutUint32(msg[offset:], uint32(keytype))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(keyidx))
	offset += 4

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_SetPrivKPin(user_type int, user_name_or_uuid []byte, keytype int, keyidx int, pin []byte) int {
	var msgLen = 44 + 4 + 4 + len(pin)
	var cmd = 0xB003
	var msg = make([]byte, msgLen)

	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	binary.BigEndian.PutUint32(msg[offset:], uint32(keytype))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(keyidx*2-1))
	offset += 4
	copy(msg[offset:], pin)

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_CreateUser(user_type int, user_name_or_uuid []byte, usertype int, name, uuid []byte, pin []byte, pubKey *ECCrefPublicKey) int {
	if name != nil && uuid != nil {
		return -1
	}

	var cmd = 0xB004
	var idflen = 32
	var pinLen = len(pin)
	if uuid != nil {
		var msgLen = 44 + 4 + 4 + idflen + 4 + pinLen + 4 + 64*2
		var msg = make([]byte, msgLen)

		var offset = 0
		binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
		offset += 4
		binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
		offset += 4
		binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
		offset += 4
		copy(msg[offset:], user_name_or_uuid)
		offset += 32
		binary.BigEndian.PutUint32(msg[offset:], uint32(usertype))
		offset += 4
		binary.BigEndian.PutUint32(msg[offset:], uint32(1))
		offset += 4
		copy(msg[offset:], uuid[:])
		offset += idflen
		binary.BigEndian.PutUint32(msg[offset:], uint32(pinLen))
		offset += 4
		copy(msg[offset:], pin)
		offset += len(pin)
		binary.BigEndian.PutUint32(msg[offset:], uint32(pubKey.Bits))
		offset += 4
		copy(msg[offset:], pubKey.X[:])
		offset += 64
		copy(msg[offset:], pubKey.Y[:])
		offset += 64

		_, err := gconn.Write(msg)
		if err != nil {
			fmt.Println("Error Send To Server:", err)
			return SEND2MS
		}
		var recvmsg = make([]byte, 8)
		_, err = gconn.Read(recvmsg)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
		var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
		return int(recvRet)
	} else {
		var msgLen = 44 + 4 + 4 + idflen + 4 + pinLen
		var msg = make([]byte, msgLen)

		var offset = 0
		binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
		offset += 4
		binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
		offset += 4
		binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
		offset += 4
		copy(msg[offset:], user_name_or_uuid)
		offset += 32
		binary.BigEndian.PutUint32(msg[offset:], uint32(usertype))
		offset += 4
		binary.BigEndian.PutUint32(msg[offset:], uint32(0))
		offset += 4
		copy(msg[offset:], name[:])
		offset += idflen
		binary.BigEndian.PutUint32(msg[offset:], uint32(pinLen))
		offset += 4
		copy(msg[offset:], pin)
		offset += len(pin)

		_, err := gconn.Write(msg)
		if err != nil {
			fmt.Println("Error Send To Server:", err)
			return SEND2MS
		}
		var recvmsg = make([]byte, 8)
		_, err = gconn.Read(recvmsg)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
		var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
		return int(recvRet)
	}
}

func Manage_DelUser(user_type int, user_name_or_uuid []byte, name, uuid []byte) int {
	if name != nil && uuid != nil {
		return -1
	}

	var idflen = 32
	var msgLen = 44 + 4 + idflen
	var cmd = 0xB005
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	if uuid != nil {
		binary.BigEndian.PutUint32(msg[offset:], uint32(1))
		offset += 4
		copy(msg[offset:offset+idflen], uuid[0:idflen])
	} else {
		binary.BigEndian.PutUint32(msg[offset:], uint32(0))
		offset += 4
		copy(msg[offset:offset+idflen], name[0:idflen])
	}

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

// ecsig : r[64] + s[64]
func Manage_VerifyUser(user_type int, user_name_or_uuid []byte,
	name, uuid []byte, pin []byte, random []byte, ecsig []byte, identity *int) int {
	if name != nil && uuid != nil {
		return -1
	}
	var cmd = 0xB006
	var msgLen = 0
	var pinlen int = len(pin)
	var name_or_uuid int
	var idf []byte
	var msg []byte
	if uuid != nil {
		msgLen = 44 + 4 + 32 + 4 + pinlen + 16 + 64 + 64
		msg = make([]byte, msgLen)
		idf = uuid
		copy(msg[84+pinlen:], random)
		copy(msg[100+pinlen:], ecsig)
		name_or_uuid = 1
	} else {
		msgLen = 44 + 4 + 32 + 4 + pinlen
		msg = make([]byte, msgLen)
		idf = name
		name_or_uuid = 0
	}

	binary.BigEndian.PutUint32(msg[0:], uint32(msgLen))
	binary.BigEndian.PutUint32(msg[4:], uint32(cmd))
	binary.BigEndian.PutUint32(msg[8:], uint32(user_type))
	copy(msg[12:], user_name_or_uuid)
	binary.BigEndian.PutUint32(msg[44:], uint32(name_or_uuid))
	copy(msg[48:], idf)
	binary.BigEndian.PutUint32(msg[80:], uint32(pinlen))
	copy(msg[84:], pin)

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvLen = binary.BigEndian.Uint32(recvmsg[0:4])
	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	if recvRet != 0 {
		return int(recvRet)
	} else {
		identitystr := make([]byte, recvLen-8)
		_, err = gconn.Read(identitystr)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
		*identity = int(binary.BigEndian.Uint32(identitystr[0:4]))
	}
	return int(recvRet)
}

func Manage_IfDevInited(user_type int, user_name_or_uuid []byte) int {
	var msgLen = 44
	var cmd = 0xB007
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_GenRootKey(user_type int, user_name_or_uuid []byte) int {
	var msgLen = 44
	var cmd = 0xB008
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_SetDevInited(user_type int, user_name_or_uuid []byte) int {
	var msgLen = 44
	var cmd = 0xB009
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

// list: type[0-4] uuidLen[4-8] uuid[8-]
func Manage_GetCurrentUserList(user_type int, user_name_or_uuid []byte, userList *[]byte) int {
	var msgLen = 44
	var cmd = 0xB00A
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvLen = binary.BigEndian.Uint32(recvmsg[0:4])
	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	if recvRet != 0 {
		return int(recvRet)
	} else {
		*userList = make([]byte, recvLen-8)
		_, err = gconn.Read(*userList)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
	}
	return int(recvRet)
}

// list: type[0-4] uuidLen[4-8] uuid[8-]
func Manage_GetCurrenKeyList(user_type int, user_name_or_uuid []byte, keytype int, keyList *[]int) int {
	var msgLen = 44 + 4
	var cmd = 0xB00B
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	binary.BigEndian.PutUint32(msg[offset:], uint32(keytype))

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvLen = binary.BigEndian.Uint32(recvmsg[0:4])
	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	if recvRet != 0 {
		return int(recvRet)
	} else {
		bkeyList := make([]byte, recvLen-8)
		_, err = gconn.Read(bkeyList)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
		var listnums = (recvLen - 8) / 4
		*keyList = make([]int, listnums)
		var i int
		for i = 0; i < int(listnums); i++ {
			(*keyList)[i] = int(binary.BigEndian.Uint32(bkeyList[i*4 : (i+1)*4]))
		}
	}
	return int(recvRet)
}

func Manage_KeyDiv(user_type int, user_name_or_uuid []byte, divtype int, keyidx int, keytype int, sigORenc int, s *[]byte) int {
	var msgLen = 44 + 4 + 4 + 4 + 4
	var cmd = 0xB00C
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	binary.BigEndian.PutUint32(msg[offset:], uint32(divtype))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(keyidx))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(keytype))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(sigORenc))
	offset += 4

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvLen = binary.BigEndian.Uint32(recvmsg[0:4])
	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	if recvRet != 0 {
		return int(recvRet)
	} else {
		*s = make([]byte, recvLen-8)
		_, err = gconn.Read(*s)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}

	}
	return int(recvRet)
}

func Manage_KeyComeback(user_type int, user_name_or_uuid []byte, divtype int, s1 []byte, s2 []byte, s3 []byte) int {
	var msgLen = 44 + 4 + 4 + len(s1) + 4 + len(s2)
	if divtype != 0 {
		msgLen += 4 + len(s3)
	}
	var cmd = 0xB00D
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	binary.BigEndian.PutUint32(msg[offset:], uint32(divtype))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(len(s1)))
	offset += 4
	copy(msg[offset:], s1)
	offset += len(s1)

	binary.BigEndian.PutUint32(msg[offset:], uint32(len(s2)))
	offset += 4

	copy(msg[offset:], s2)
	offset += len(s2)

	if divtype != 0 {
		binary.BigEndian.PutUint32(msg[offset:], uint32(len(s3)))
		offset += 4
		copy(msg[offset:], s3)
		offset += len(s3)
	}

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_RestartMServer(user_type int, user_name_or_uuid []byte) int {
	var msgLen = 44
	var cmd = 0xB00E
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_ResetAll(user_type int, user_name_or_uuid []byte) int {
	var msgLen = 44
	var cmd = 0xB00F
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_DevSelfCheck(user_type int, user_name_or_uuid []byte, flag byte) int {
	var msgLen = 44 + 1
	var cmd = 0xB010
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	msg[offset] = flag
	offset += 1

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_GetDevInfo(user_type int, user_name_or_uuid []byte, devinfo *DeviceInof) int {
	var msgLen = 44
	var cmd = 0xB011
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}
	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvLen = binary.BigEndian.Uint32(recvmsg[0:4])
	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	if recvRet != 0 {
		return int(recvRet)
	} else {
		recvmsg2 := make([]byte, recvLen-8)
		_, err = gconn.Read(recvmsg2)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
		var offset = 0
		copy(devinfo.IssuerName[:], recvmsg2[offset:])
		offset += 40
		copy(devinfo.DeviceName[:], recvmsg2[offset:])
		offset += 16
		copy(devinfo.DeviceSerial[:], recvmsg2[offset:])
		offset += 16
		devinfo.DeviceVersion = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		devinfo.StandardVersion = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		devinfo.AsymAlgAbility[0] = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		devinfo.AsymAlgAbility[1] = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		devinfo.SymAlgAbility = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		devinfo.HashAlgAbility = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		devinfo.BufferSize = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
	}
	return int(recvRet)
}

func Manage_GetSysStatus(user_type int, user_name_or_uuid []byte, Sysinfo *SysInfo) int {
	var msgLen = 44
	var cmd = 0xB012
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvLen = binary.BigEndian.Uint32(recvmsg[0:4])
	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	if recvRet != 0 {
		return int(recvRet)
	} else {
		recvmsg2 := make([]byte, recvLen-8)
		_, err = gconn.Read(recvmsg2)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
		var offset = 0
		Sysinfo.UpTime = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		Sysinfo.CpuUsage = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
		Sysinfo.MemoryUsage = uint(binary.BigEndian.Uint32(recvmsg2[offset:]))
		offset += 4
	}
	return int(recvRet)
}

func Manage_GetInterfaceInfo(user_type int, user_name_or_uuid []byte, Itfinfo *[]IPV4_InterfaceInfo) int {
	var msgLen = 44
	var cmd = 0xB013
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvLen = binary.BigEndian.Uint32(recvmsg[0:4])
	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	if recvRet != 0 {
		return int(recvRet)
	} else {
		recvmsg2 := make([]byte, recvLen-8)
		_, err = gconn.Read(recvmsg2)
		if err != nil {
			fmt.Println("Error Recv From Server:", err)
			return RECVFROMMS
		}
		var offset = 0
		var itfnums = len(recvmsg2) / (16 + 4 + 4 + 4 + 4)
		interfaces := make([]IPV4_InterfaceInfo, itfnums)
		for i := 0; i < itfnums; i++ {
			copy(interfaces[i].Name[:], recvmsg2[offset:offset+16])
			offset += 16
			copy(interfaces[i].IP[:], recvmsg2[offset:offset+4])
			offset += 4
			copy(interfaces[i].Gateway[:], recvmsg2[offset:offset+4])
			offset += 4
			copy(interfaces[i].Netmask[:], recvmsg2[offset:offset+4])
			offset += 4
			interfaces[i].IsActive = int(binary.BigEndian.Uint32(recvmsg2[offset:]))
			offset += 4
		}
		*Itfinfo = interfaces
	}
	return int(recvRet)
}

func Manage_ModifyInterfaceInfo(user_type int, user_name_or_uuid []byte, Itfinfo *IPV4_InterfaceInfo) int {
	var msgLen = 44 + 16 + 4 + 4 + 4
	var cmd = 0xB014
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32
	copy(msg[offset:], Itfinfo.Name[:16])
	offset += 16
	copy(msg[offset:], Itfinfo.IP[:4])
	offset += 4
	copy(msg[offset:], Itfinfo.Gateway[:4])
	offset += 4
	copy(msg[offset:], Itfinfo.Netmask[:4])
	offset += 4

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_SetWhitTable(user_type int, user_name_or_uuid []byte, cidr []byte) int {
	var msgLen = 44 + len(cidr)
	var cmd = 0xB015
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	copy(msg[offset:], cidr)
	offset += len(cidr)

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}

func Manage_DelWhitTable(user_type int, user_name_or_uuid []byte, cidr []byte) int {
	var msgLen = 44 + len(cidr)
	var cmd = 0xB016
	var msg = make([]byte, msgLen)
	var offset = 0
	binary.BigEndian.PutUint32(msg[offset:], uint32(msgLen))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(cmd))
	offset += 4
	binary.BigEndian.PutUint32(msg[offset:], uint32(user_type))
	offset += 4
	copy(msg[offset:], user_name_or_uuid)
	offset += 32

	copy(msg[offset:], cidr)
	offset += len(cidr)

	_, err := gconn.Write(msg)
	if err != nil {
		fmt.Println("Error Send To Server:", err)
		return SEND2MS
	}

	var recvmsg = make([]byte, 8)
	_, err = gconn.Read(recvmsg)
	if err != nil {
		fmt.Println("Error Recv From Server:", err)
		return RECVFROMMS
	}

	var recvRet = binary.BigEndian.Uint32(recvmsg[4:8])
	return int(recvRet)
}
