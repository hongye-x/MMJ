package main

/*
#cgo LDFLAGS:
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	msAPI "sig_vfy/src/mserver/API"
	"sig_vfy/src/usermanage"
)

var currentUserNameOrUUID []byte
var currentUserType int

func genusers() int {
	var admin1uuid = "admin1"
	var operater1uuid = "operator1"
	var audit1uuid = "audit1"

	var userList = []string{
		admin1uuid,
		operater1uuid,
		audit1uuid}

	var usertypeList = []int{
		usermanage.USER_TYPE_ADMIN,
		usermanage.USER_TYPE_OPERA,
		usermanage.USER_TYPE_AUDIT}

	var i = 0

	for i = 0; i < len(userList); i++ {
		uuid := userList[i]
		usertype := usertypeList[i]
		filename := "../user/" + uuid + "/pubk"
		fp, err := os.Open(filename)
		if err != nil {
			fmt.Println(err)
		}

		var pubk = make([]byte, 256)
		_, err = fp.Read(pubk)
		if err != nil {
			fmt.Println(err)
		}

		var pubKey msAPI.ECCrefPublicKey
		pubKey.Bits = 256
		copy(pubKey.X[:], pubk[:64])
		copy(pubKey.Y[:], pubk[64:])

		fmt.Printf("请输入 %s 用户PIN码:", uuid)
		exec.Command("sh", "-c", "stty -echo < /dev/tty").Run()
		var userPin string
		fmt.Scanln(&userPin)
		exec.Command("sh", "-c", "stty echo < /dev/tty").Run()

		stderr := msAPI.Manage_CreateUser(currentUserType, currentUserNameOrUUID,
			usertype, []byte(uuid), nil, []byte(userPin), nil)
		if stderr != 0 {
			return stderr
		}
		fmt.Printf("\n%s 创建成功\n", uuid)
	}

	return 0
}

func devinit() {
	var iret int
	var choice string
	fmt.Printf("设备还未初始化\n")
	fmt.Printf("是否生成主密钥[Y/N]:")
	fmt.Scanln(&choice)
	if choice[0] == 'Y' || choice[0] == 'y' {
		iret = msAPI.Manage_GenRootKey(currentUserType, currentUserNameOrUUID)
		if iret != 0 {
			fmt.Printf("生成主密钥失败 错误码 : %08X\n", iret)
		}
	} else {
		return
	}
	fmt.Printf("主密钥生成成功\n")

	fmt.Printf("是否生成用户[Y/N]:")
	fmt.Scanln(&choice)
	if choice[0] == 'Y' || choice[0] == 'y' {
		fmt.Println("注:软算法模式下,自动生成admin1,operator1,audit1,共3个角色")
		iret = genusers()
		if iret != 0 {
			fmt.Printf("用户生成失败 错误码 : %08X\n", iret)
		}
	} else {
		return
	}

	iret = msAPI.Manage_SetDevInited(currentUserType, currentUserNameOrUUID)
	if iret != 0 {
		fmt.Printf("设置初始化状态失败 错误码 : %08X\n", iret)
	}
	fmt.Println("设备初始化成功!")

	iret = msAPI.Manage_RestartMServer(currentUserType, currentUserNameOrUUID)
	if iret != 0 {
		fmt.Printf("管理服务重启失败 错误码 : %08X\n", iret)
	} else {
		fmt.Println("管理服务重启成功!")
	}
	os.Exit(0)
}

func superMainMenu() int {
	var choice int
	fmt.Println(`********************
1.创建用户		 	
2.删除用户
3.获取用户列表		 	
4.生成密钥		 	
5.删除密钥		 	
6.查询密钥列表		
7.密钥备份			
8.密钥恢复			
9.恢复出厂设置
0.退出
********************
选择功能:`)
	fmt.Scanln(&choice)
	return choice
}

func adminMainMenu() int {
	var choice int = 999
	fmt.Println(`********************
1.创建用户		 	
2.删除用户
3.获取用户列表		 	
4.恢复出厂设置
0.退出
********************
选择功能:`)
	fmt.Scanln(&choice)
	return choice
}

func operMainMenu() int {
	var choice int = 999
	fmt.Println(`********************	 	
1.生成密钥		 	
2.删除密钥		 	
3.查询密钥列表		
4.密钥备份			
5.密钥恢复			
0.退出
********************
选择功能:`)
	fmt.Scanln(&choice)
	return choice
}

func audiMainMenu() int {
	var choice int = 999
	fmt.Println(`********************	 		
0.退出
********************
选择功能:`)
	fmt.Scanln(&choice)
	return choice
}

func createUserMenu() {
	var choice int
	var i int
	var admin1uuid = "admin1"
	var admin2uuid = "admin2"
	var admin3uuid = "admin3"
	var operater1uuid = "operator1"
	var operater2uuid = "operator2"
	var operater3uuid = "operator3"
	var audit1uuid = "audit1"

	var userList = []string{
		admin1uuid, admin2uuid, admin3uuid,
		operater1uuid, operater2uuid, operater3uuid,
		audit1uuid}

	var usertypeList = []int{
		usermanage.USER_TYPE_ADMIN, usermanage.USER_TYPE_ADMIN, usermanage.USER_TYPE_ADMIN,
		usermanage.USER_TYPE_OPERA, usermanage.USER_TYPE_OPERA, usermanage.USER_TYPE_OPERA,
		usermanage.USER_TYPE_AUDIT}

	var usertypeStrList = []string{
		"管理员", "管理员", "管理员",
		"操作员", "操作员", "操作员",
		"审计员"}

	fmt.Println("*****************************")
	fmt.Printf("索引\t类型\tUUID\n")
	for i = 0; i < len(userList); i++ {
		fmt.Printf("%d.\t%s\t%s\n", i+1, usertypeStrList[i], userList[i])
	}
	fmt.Printf("注:软算法模式下 用户UUID固定为以上\n")
	fmt.Println("*****************************")
	fmt.Printf("选择想要创建的用户:")
	fmt.Scanln(&choice)
	if choice == 0 {
		return
	}

	choice -= 1
	userUUID := userList[choice]
	userType := usertypeList[choice]

	filename := "../user/" + userUUID + "/pubk"
	fp, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return

	}

	var pubk = make([]byte, 256)
	_, err = fp.Read(pubk)
	if err != nil {
		fmt.Println(err)
		return

	}

	var pubKey msAPI.ECCrefPublicKey
	pubKey.Bits = 256
	copy(pubKey.X[:], pubk[:64])
	copy(pubKey.Y[:], pubk[64:])

	fmt.Printf("请输入用户PIN码:")
	exec.Command("sh", "-c", "stty -echo < /dev/tty").Run()
	var userPin string
	fmt.Scanln(&userPin)
	exec.Command("sh", "-c", "stty echo < /dev/tty").Run()

	iret := msAPI.Manage_CreateUser(currentUserType, currentUserNameOrUUID,
		userType, []byte(userUUID), nil, []byte(userPin), &pubKey)
	if iret != 0 {
		fmt.Printf("创建用户失败 错误码 : %08X\n", iret)
	} else {
		fmt.Println("创建用户成功!")
	}

	fmt.Println("按回车键返回上一级")
	fmt.Scanln(&choice)
}

func delUserMenu() {
	var userList []byte
	iret := msAPI.Manage_GetCurrentUserList(currentUserType, currentUserNameOrUUID,
		&userList)
	if iret != 0 {
		fmt.Printf("获取用户列表失败 错误码 : %08X\n", iret)
		return
	}
	var i int
	var offset int = 0
	userUuidListMap := make(map[int][]byte)
	userTypeListMap := make(map[int][]byte)

	for i = 0; offset < len(userList); i++ {
		userType := binary.BigEndian.Uint32(userList[offset:])
		offset += 4
		userUuidLen := binary.BigEndian.Uint32(userList[offset:])
		offset += 4
		userUuid := userList[offset : offset+int(userUuidLen)]
		offset += int(userUuidLen)

		if userType == 0 {
			userTypeListMap[i] = []byte("管理员")
		} else if userType == 1 {
			userTypeListMap[i] = []byte("操作员")
		} else if userType == 2 {
			userTypeListMap[i] = []byte("审计员")
		}
		userUuidListMap[i] = []byte(userUuid)
	}

	fmt.Println("*****************************")
	fmt.Printf("索引\t类型\tUUID\n")
	for i = 0; i < len(userTypeListMap); i++ {
		fmt.Printf("%d.\t%s\t%s\n", i+1, userTypeListMap[i], userUuidListMap[i])
	}
	fmt.Println("*****************************")
	fmt.Printf("选择想要删除的用户:")
	var choice int
	fmt.Scanln(&choice)
	if choice == 0 {
		return
	}
	choice -= 1

	iret = msAPI.Manage_DelUser(currentUserType, currentUserNameOrUUID,
		userUuidListMap[choice], nil)
	if iret != 0 {
		fmt.Printf("\n删除用户失败 错误码 : %08X\n\n", iret)
	} else {
		fmt.Printf("\n删除用户成功!\n\n")
	}

	fmt.Println("按回车键返回上一级")
	fmt.Scanln(&choice)
}

func getUserListMenu() {
	var userList []byte
	iret := msAPI.Manage_GetCurrentUserList(currentUserType, currentUserNameOrUUID, &userList)
	if iret != 0 {
		fmt.Printf("获取用户列表失败 错误码 : %08X\n", iret)
		return
	}
	var i int
	var offset int = 0
	userUuidListMap := make(map[int][]byte)
	userTypeListMap := make(map[int][]byte)

	for i = 0; offset < len(userList); i++ {
		userType := binary.BigEndian.Uint32(userList[offset:])
		offset += 4
		userUuidLen := binary.BigEndian.Uint32(userList[offset:])
		offset += 4
		userUuid := userList[offset : offset+int(userUuidLen)]
		offset += int(userUuidLen)

		if userType == 0 {
			userTypeListMap[i] = []byte("管理员")
		} else if userType == 1 {
			userTypeListMap[i] = []byte("操作员")
		} else if userType == 2 {
			userTypeListMap[i] = []byte("审计员")
		}
		userUuidListMap[i] = []byte(userUuid)
	}

	fmt.Println("*****************************")
	fmt.Printf("索引\t类型\tUUID\n")
	for i = 0; i < len(userTypeListMap); i++ {
		fmt.Printf("%d.\t%s\t%s\n", i+1, userTypeListMap[i], userUuidListMap[i])
	}
	fmt.Println("*****************************")
	fmt.Println("按回车键返回上一级")
	var choice string
	fmt.Scanln(&choice)
}

func genKeyMenu() {
	var keyType int
	var keyIdx int
	var sigOrEnc int
	var keyBits int
	var pswd string
	var bpswd []byte

	fmt.Printf("选择想要生成的密钥类型(1.sym;2.RSA;3.ECC):")
	fmt.Scanln(&keyType)

	keyType -= 1
	if keyType == 1 {
		fmt.Println("不支持RSA密钥对")
		return
	}
	if keyType != 0 && keyType != 2 {
		return
	}

	fmt.Printf("输入待生成的密钥索引:")
	fmt.Scanln(&keyIdx)

	if keyType == 0 {
		fmt.Printf("密钥大小(1.128bits):")
		fmt.Scanln(&keyBits)
		if keyBits != 1 {
			return
		}
		keyBits = 128
		bpswd = nil
	} else if keyType == 2 {
		fmt.Printf("加密或签名密钥(1.sig;2.enc):")
		fmt.Scanln(&sigOrEnc)
		if sigOrEnc != 1 && sigOrEnc != 2 {
			return
		}
		sigOrEnc -= 1

		fmt.Printf("密钥大小(1.256bits):")
		fmt.Scanln(&keyBits)
		if keyBits != 1 {
			return
		}
		keyBits = 256

		exec.Command("sh", "-c", "stty -echo < /dev/tty").Run()
		fmt.Printf("设置私钥授权码(可为空):")
		fmt.Scanln(&pswd)
		exec.Command("sh", "-c", "stty echo < /dev/tty").Run()
		bpswd = []byte(pswd)
	}

	iret := msAPI.Manage_GenKey(currentUserType, currentUserNameOrUUID, keyType, keyIdx, sigOrEnc, keyBits, bpswd)
	if iret != 0 {
		fmt.Printf("\n生成密钥失败 错误码 : %08X\n", iret)
	} else {
		fmt.Printf("\n生成密钥成功\n")
	}
	fmt.Println("按回车键返回上一级")
	var choice string
	fmt.Scanln(&choice)
}

func delKeyMenu() {
	var keyType int
	var keyIdx int
	var sigOrEnc int

	fmt.Printf("选择想要删除的密钥类型(1.sym;2.RSA;3.ECC):")
	fmt.Scanln(&keyType)
	keyType -= 1
	if keyType == 1 {
		fmt.Println("不支持RSA密钥对")
		return
	}
	if keyType != 0 && keyType != 2 {
		return
	}

	fmt.Printf("输入待删除的密钥索引:")
	fmt.Scanln(&keyIdx)
	if keyType == 2 {
		fmt.Printf("加密或签名密钥(1.sig;2.enc):")
		fmt.Scanln(&sigOrEnc)
		if sigOrEnc != 1 && sigOrEnc != 2 {
			return
		}
		sigOrEnc -= 1
	}

	iret := msAPI.Manage_DelKey(currentUserType, currentUserNameOrUUID,
		keyType, keyIdx, sigOrEnc)
	if iret != 0 {
		fmt.Printf("\n删除密钥失败 错误码 : %08X\n", iret)
	} else {
		fmt.Printf("\n删除密钥成功\n")
	}
	fmt.Println("按回车键返回上一级")
	var choice string
	fmt.Scanln(&choice)
}

type a struct {
	keyidx int
	sigkey byte
	enckey byte
	pivpin byte
}

func getKeyListMenu() {
	var keyType int

	fmt.Printf("选择想要查询的密钥类型(1.sym;2.RSA;3.ECC):")
	fmt.Scanln(&keyType)

	keyType -= 1
	if keyType == 1 {
		fmt.Println("不支持RSA密钥对")
		return
	}
	if keyType != 0 && keyType != 2 {
		return
	}

	var keyList []int
	iret := msAPI.Manage_GetCurrenKeyList(currentUserType, currentUserNameOrUUID,
		keyType, &keyList)
	if iret != 0 {
		fmt.Printf("\n获取密钥列表失败 错误码 : %08X\n", iret)
		return
	}

	var i, j int
	var alist = make([]a, 1024*2)
	if keyType == 0 {
		fmt.Printf("密钥索引\n")
		for i = 0; i < len(keyList); i++ {
			fmt.Printf("%d\n", keyList[i])
		}
	} else if keyType == 2 {
		fmt.Printf("密钥索引\t签名密钥\t加密密钥\t私钥授权码\n")
		for i = 0; i < len(keyList); i++ {
			var ifPin byte = '/'
			var keyidx int
			var sigflag byte
			var encflag byte
			if keyList[i]&0x80000000 == 0x80000000 {
				ifPin = 'Y'
				keyList[i] &= 0x0FFFFFFF
			}
			if keyList[i]%2 == 0 {
				keyidx = keyList[i] / 2
				encflag = 'Y'
				sigflag = '/'
			} else {
				if i != len(keyList)-1 {
					if keyList[i+1]&0x0FFFFFFF == keyList[i]+1 {
						if keyList[i+1]&0x80000000 == 0x80000000 {
							ifPin = 'Y'
						}
						keyidx = (keyList[i] + 1) / 2
						encflag = 'Y'
						sigflag = 'Y'
						i++
					} else {
						keyidx = (keyList[i] + 1) / 2
						encflag = '/'
						sigflag = 'Y'
					}

				} else {
					keyidx = (keyList[i] + 1) / 2
					encflag = '/'
					sigflag = 'Y'
				}
			}

			alist[j].keyidx = keyidx
			alist[j].pivpin = ifPin
			alist[j].sigkey = sigflag
			alist[j].enckey = encflag
			j++
		}
		for i = 0; i < j; i++ {
			fmt.Printf("%d\t\t%c\t\t%c\t\t%c\n", alist[i].keyidx, alist[i].sigkey, alist[i].enckey, alist[i].pivpin)
		}
	}
	fmt.Println("\n按回车键返回上一级")
	var choice string
	fmt.Scanln(&choice)
}

func keyDivMenu() {
	var divType int
	var keyType int
	var keyIdx int
	var keyTypeName string

	fmt.Printf("选择想要备份的模式(1.3门2;2.5门3):")
	fmt.Scanln(&divType)
	if divType != 1 && divType != 2 {
		return
	}

	divType -= 1
	fmt.Printf("选择想要备份的密钥类型(1.sym;2.RSA;3.ECC):")
	fmt.Scanln(&keyType)

	keyType -= 1
	if keyType == 1 {
		fmt.Println("不支持RSA密钥对")
		keyTypeName = "RSA"
		return
	}
	if keyType != 0 && keyType != 2 {
		return
	}
	var sigOrEnc int

	fmt.Printf("输入待备份的密钥索引:")
	fmt.Scanln(&keyIdx)
	if keyType == 0 {
		keyTypeName = "Sym"
	} else if keyType == 2 {
		keyTypeName = "ECC"
		fmt.Printf("加密或签名密钥(1.sig;2.enc):")
		fmt.Scanln(&sigOrEnc)

	}

	var s []byte
	iret := msAPI.Manage_KeyDiv(currentUserType, currentUserNameOrUUID,
		divType, keyIdx, keyType, sigOrEnc, &s)
	if iret != 0 {
		fmt.Printf("\n密钥导出失败 错误码 : %08X\n", iret)
		return
	}
	fmt.Println("密钥导出成功")
	var rfilePath string
	fmt.Printf("请输入分量存储的位置:")
	fmt.Scanln(&rfilePath)
	info, err := os.Stat(rfilePath)
	if os.IsNotExist(err) {
		fmt.Printf("%s 不存在的目录\n", rfilePath)
		return
	}
	if !info.IsDir() {
		fmt.Printf("%s 非目录\n", rfilePath)
		return
	}

	if rfilePath[len(rfilePath)-1] == '/' {
		rfilePath = rfilePath[:len(rfilePath)-1]
	}
	var i int
	var ay = 0
	if divType == 0 {
		ay = 3
	} else if divType == 1 {
		ay = 5
	}

	var offset = 0
	for i = 0; i < ay; i++ {
		filePaht := fmt.Sprintf("%s/%s_%d.%d", rfilePath, keyTypeName, keyIdx, i+1)
		fp, err := os.OpenFile(filePaht, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			fmt.Println("文件创建失败")
		}
		defer fp.Close()

		len := binary.BigEndian.Uint32(s[offset:])
		offset += 4
		fp.Write(s[offset : offset+int(len)])
		offset += int(len)

		fmt.Printf("分量%d存储成功,存储位置:%s\n", i, filePaht)
	}
	fmt.Println("分量存储成功")
	fmt.Println("\n按回车键返回上一级")
	var choice string
	fmt.Scanln(&choice)
}

func keyComebackMenu() {
	var divType int
	var s1, s2, s3 []byte

	fmt.Printf("选择想要恢复的模式(1.3门2;2.5门3):")
	fmt.Scanln(&divType)
	if divType != 1 && divType != 2 {
		return
	}
	divType -= 1

	var s1path string
	fmt.Printf("输入分量1文件路径:")
	fmt.Scanln(&s1path)
	info, err := os.Stat(s1path)
	if os.IsNotExist(err) {
		fmt.Printf("%s 不存在的目录\n", s1path)
		return
	}
	if info.IsDir() {
		fmt.Printf("%s 非文件\n", s1path)
		return
	}

	s1, err = os.ReadFile(s1path)
	if err != nil {
		fmt.Println("文件读取失败")
	}

	var s2path string
	fmt.Printf("输入分量2文件路径:")
	fmt.Scanln(&s2path)
	info, err = os.Stat(s2path)
	if os.IsNotExist(err) {
		fmt.Printf("%s 不存在的目录\n", s2path)
		return
	}
	if info.IsDir() {
		fmt.Printf("%s 非文件\n", s2path)
		return
	}
	s2, err = os.ReadFile(s2path)
	if err != nil {
		fmt.Println("文件读取失败")
	}

	var s3path string
	if divType == 1 {
		fmt.Printf("输入分量3文件路径:")
		fmt.Scanln(&s3path)
		info, err = os.Stat(s3path)
		if os.IsNotExist(err) {
			fmt.Printf("%s 不存在的目录\n", s3path)
			return
		}
		if info.IsDir() {
			fmt.Printf("%s 非文件\n", s3path)
			return
		}
		s3, err = os.ReadFile(s3path)
		if err != nil {
			fmt.Println("文件读取失败")
		}
	}

	iret := msAPI.Manage_KeyComeback(currentUserType, currentUserNameOrUUID, divType, s1, s2, s3)
	if iret != 0 {
		fmt.Printf("\n密钥恢复失败 错误码 : %08X\n", iret)
		return
	}
	fmt.Println("密钥恢复成功")
	fmt.Println("\n按回车键返回上一级")
	var choice string
	fmt.Scanln(&choice)
}

func factoryDataResetMenu() {
	var choice1, choice2 string
	fmt.Printf("确认是否恢复出厂设置[Y/N]:")
	fmt.Scanln(&choice1)

	if choice1[0] == 'Y' || choice1[0] == 'y' {
		fmt.Printf("该操作不可逆,请再次确认[Y/N]:")
		fmt.Scanln(&choice2)

		if choice2[0] == 'Y' || choice2[0] == 'y' {
			iret := msAPI.Manage_ResetAll(currentUserType, currentUserNameOrUUID)
			if iret != 0 {
				fmt.Printf("生成主密钥失败 错误码 : %08X\n", iret)
			} else {
				fmt.Println("销毁成功")
				os.Exit(0)
				return
			}
			return
		}
	} else {
		return
	}
}

func otherfunction() {
	fmt.Printf("请输入用户UUID:")
	var userUUID string
	fmt.Scanln(&userUUID)
	fmt.Printf("请输入用户PIN码:")
	exec.Command("sh", "-c", "stty -echo < /dev/tty").Run()
	var userPin string
	fmt.Scan(&userPin)
	exec.Command("sh", "-c", "stty echo < /dev/tty").Run()

	/* 该部分实际业务场景中 应由Ukey负责完成，由于没有环境，只能先由软算法库模拟完成 */
	/* ******************************************** */
	devh, iret := ISDF.OpenDevice()
	if iret != 0 {
		fmt.Printf("\nUkey 调用失败!\n\n")
		return
	}
	defer ISDF.CloseDevice(devh)

	sesh, iret := ISDF.OpenSession(devh)
	if iret != 0 {
		fmt.Printf("\nUkey 调用失败!\n")
		return
	}
	defer ISDF.CloseSession(sesh)

	r, iret := ISDF.GenerateRandom(sesh, 16)
	if iret != 0 {
		fmt.Printf("\nUkey 随机数生成失败!\n")
		return
	}

	rDigest, iret := ISDF.Hash(sesh, r)
	if iret != 0 {
		fmt.Printf("\nUkey 调用失败!\n\n")
		return
	}

	filename := "../user/" + userUUID + "/pivk"
	fp, err := os.Open(filename)
	if err != nil {
		fmt.Printf("\nUkey 获取用户私钥失败!\n")
	}
	defer fp.Close()

	var pivk = make([]byte, 256)
	n, err := fp.Read(pivk)
	if err != nil {
		fmt.Printf("\nUkey 获取用户私钥失败!\n")
	}

	var pivKey ISDF.ECCrefPrivateKey
	pivKey.Bits = 256
	copy(pivKey.K[:], pivk[:n])

	ecsig, iret := ISDF.ExternalSignECC(sesh, ISDF.SGD_SM2, &pivKey, rDigest)
	if iret != 0 {
		fmt.Printf("\nUkey 签名失败!\n")
		return
	}
	becsig := b.ConcatSlices(ecsig.R[:], ecsig.S[:])

	/* ******************************************** */
	var usertype int
	var usertypeList = []string{"管理员", "操作员", "审计员"}
	iret = msAPI.Manage_VerifyUser(currentUserType, currentUserNameOrUUID,
		[]byte(userUUID), nil, []byte(userPin), r, becsig, &usertype)
	if iret != 0 {
		fmt.Printf("\n用户验证失败 错误码 : %08X\n\n", iret)
		return
	} else {
		fmt.Printf("\n%s 用户验证成功!\n\n", usertypeList[usertype])
		currentUserType = usertype
		currentUserNameOrUUID = []byte(userUUID)
	}
	if usertype == 0 {
		for {
			choice := adminMainMenu()
			if choice == 1 {
				createUserMenu()
			} else if choice == 2 {
				delUserMenu()
			} else if choice == 3 {
				getUserListMenu()
			} else if choice == 4 {
				factoryDataResetMenu()
			} else if choice == 0 {
				os.Exit(0)
			} else {
				fmt.Println("无效输入")
			}
		}

	} else if usertype == 1 {
		for {
			choice := operMainMenu()
			if choice == 1 {
				genKeyMenu()
			} else if choice == 2 {
				delKeyMenu()
			} else if choice == 3 {
				getKeyListMenu()
			} else if choice == 4 {
				keyDivMenu()
			} else if choice == 5 {
				keyComebackMenu()
			} else if choice == 0 {
				os.Exit(0)
			} else {
				fmt.Println("无效输入")
			}
		}
	} else if usertype == 2 {
		for {
			choice := audiMainMenu()
			if choice == 1 {
				os.Exit(0)
			} else {
				os.Exit(0)
			}
		}
	}

	// for {
	// 	choice := superMainMenu()
	// 	if choice == 1 {
	// 		createUserMenu()
	// 	} else if choice == 2 {
	// 		delUserMenu()
	// 	} else if choice == 3 {
	// 		getUserListMenu()
	// 	} else if choice == 4 {
	// 		genKeyMenu()
	// 	} else if choice == 5 {
	// 		delKeyMenu()
	// 	} else if choice == 6 {
	// 		getKeyListMenu()
	// 	} else if choice == 7 {
	// 		keyDivMenu()
	// 	} else if choice == 8 {
	// 		keyComebackMenu()
	// 	} else if choice == 9 {
	// 		factoryDataResetMenu()
	// 	} else {
	// 		os.Exit(0)
	// 	}
	// }
}

func main() {
	list, stderr := b.ReadConfigValues("MANAGE_SERVER_IP", "MANAGE_SERVER_PORT")
	if stderr != nil {
		b.PrintStdErr(stderr)
		return
	}
	ip := list["MANAGE_SERVER_IP"].([]byte)
	port := list["MANAGE_SERVER_PORT"].(int)
	Server_IP := fmt.Sprintf("%s:%d", ip, port)
	fmt.Printf("连接管理服务 : %s\n", Server_IP)
	currentUserNameOrUUID = []byte("manageTool")
	currentUserType = 129
	for {
		devinitflag := msAPI.Manage_IfDevInited(currentUserType, currentUserNameOrUUID)
		if devinitflag == 0 {
			devinit()
		} else {
			fmt.Println("注:软算法模式下,UUID为输入形式,UKey场景中,UUID自动读取")
			otherfunction()
		}
	}
}
