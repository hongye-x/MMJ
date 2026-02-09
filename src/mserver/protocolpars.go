package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"sig_vfy/src/initialize"
	"sig_vfy/src/keymanage"
	slog "sig_vfy/src/log"
	"sig_vfy/src/sqlop"
	"sig_vfy/src/usermanage"
	w "sig_vfy/src/whitetable"
	"time"
	"unsafe"
)

func sendErrorMsgBack(conn net.Conn, uiret int) {
	rtmsg := make([]byte, 8)
	binary.BigEndian.PutUint32(rtmsg, uint32(8))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	conn.Write(rtmsg)
}

func ParsMsgAndSend(conn net.Conn) *b.StdErr {
	// timeoutDuration := 5 * time.Second //5s
	// conn.SetDeadline(time.Now().Add(timeoutDuration))

	var msg = make([]byte, b.RECVMAXLEN_ONCE/1024)
	reader := bufio.NewReader(conn)
	for {
		rdlen, err := reader.Read(msg)
		if err != nil {
			conn.Close()
			RWmu.Lock()
			ManSerStatus.ConnNums--
			RWmu.Unlock()
			return nil
		}
		if rdlen < 8 {
			return nil
		}

		var offset int = 0
		var totalLen int
		var cmd int
		totalLen = int(binary.BigEndian.Uint32(msg[offset : offset+4]))
		offset += 4
		cmd = int(binary.BigEndian.Uint32(msg[offset : offset+4]))
		offset += 4
		usertype := int(binary.BigEndian.Uint32(msg[offset : offset+4]))
		offset += 4
		useruuid := msg[offset : offset+32]
		offset += 32

		msgbody := msg[offset:totalLen]
		switch cmd {
		case 0xB001:
			stderr := mGenKey(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Generate Key Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Generate Key Success")
			}

		case 0xB002:
			stderr := mDelKey(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Delete Key Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Delete Key Success")
			}

		case 0xB003:
			stderr := mSetPrivKPin(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Set Private Key Pin Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Set Private Key Pin Success")
			}

		case 0xB004:
			stderr := mCreateUser(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Create User Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Create User Success")
			}

		case 0xB005:
			stderr := mDelUser(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Delete User Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Delete User Success")
			}

		case 0xB006:
			stderr := mVerifyUser(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Verify User Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Verify User Success")
			}

		case 0xB007:
			stderr := mIfDevInited(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Get Device Init Status Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Get Device Init Status Success")
			}

		case 0xB008:
			stderr := mGenRootKey(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Generate Root Key Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Generate Root Key Success")
			}

		case 0xB009:
			stderr := mSetDevInited(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Set Device Init Status Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Set Device Init Status Success")
			}

		case 0xB00A:
			stderr := mGetCurrentUserList(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB00B:
			stderr := mGetCurrentKeyList(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB00C:
			stderr := mKeyDiv(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Key Dived Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Key Dived Init Status Success")
			}

		case 0xB00D:
			stderr := mKeyComeBack(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Key Come Back Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Key Come Back Init Status Success")
			}

		case 0xB00E:
			stderr := mRestartMserver(conn, msgbody)
			if stderr != nil {
				slog.MServerLogWrite(slog.Error, usertype, useruuid,
					"Restart Manage Server Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.MServerLogWrite(slog.Info, usertype, useruuid,
					"Restart Manage Server Success")
			}

		case 0xB00F:
			stderr := mResetAll(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB010:
			stderr := mDevSelfCheck(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB011:
			stderr := mGetDevInfo(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB012:
			stderr := mGetSysStatus(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB013:
			stderr := mGetIntfInfo(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB014:
			stderr := mModifyItfInfo(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB015:
			stderr := mAddWhiteTable(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}

		case 0xB016:
			stderr := mDelWhiteTable(conn, msgbody)
			if stderr != nil {
				b.PrintStdErr(stderr)
			}
		default:
			sendErrorMsgBack(conn, int(b.UNKNOW_CMD))
		}
	}
}

// 1. 生成密钥
// 0xB001
// rcv msg : keytype[0-4] keybits[4-8] keyidx[8-12] pswd[12-]
// snd msg :
func mGenKey(conn net.Conn, msg []byte) *b.StdErr {
	if MDevInitedFlag != 1 {
		sendErrorMsgBack(conn, b.DEV_NOT_INITED)
		return b.CreateStdErr(int(b.DEV_NOT_INITED),
			"GenKey Error Device Has Not Been Initialized")
	}

	keytype := binary.BigEndian.Uint32(msg[0:])
	keybits := binary.BigEndian.Uint32(msg[4:])
	keyidx := binary.BigEndian.Uint32(msg[8:])
	var key interface{}
	if keytype == uint32(keymanage.SYM_TYPE_FLAG) {
		r, uiret := ISDF.GenerateRandom(MSSesH, int(keybits)/8)
		if uiret != 0 {
			sendErrorMsgBack(conn, uiret)
			return b.CreateStdErr(int(uiret),
				"GenKey Error ret : %08X", uiret)
		}
		key = &keymanage.MemStorSymKey{}
		key.(*keymanage.MemStorSymKey).Idx = int(keyidx)
		key.(*keymanage.MemStorSymKey).KeyBits = int(keybits)
		key.(*keymanage.MemStorSymKey).KeyValue = r
	} else if keytype == uint32(keymanage.SM2_TYPE_FLAG) {
		ecpubk, ecpivk, uiret := ISDF.GenerateKeyPairECC(MSSesH, ISDF.SGD_SM2, int(keybits))
		if uiret != 0 {
			sendErrorMsgBack(conn, uiret)
			return b.CreateStdErr(int(uiret),
				"GenKey Error ret : %08X", uiret)
		}
		key = &keymanage.MemStorSM2Key{}
		key.(*keymanage.MemStorSM2Key).Idx = int(keyidx)
		key.(*keymanage.MemStorSM2Key).PubKey = *ecpubk
		key.(*keymanage.MemStorSM2Key).PrivKey = *ecpivk
		if len(msg) > 12 {
			digest, uiret := ISDF.Hash(MSSesH, msg[12:])
			if uiret != 0 {
				sendErrorMsgBack(conn, uiret)
				return b.CreateStdErr(int(uiret),
					"GenKey Error ret : %08X", uiret)
			}
			copy(key.(*keymanage.MemStorSM2Key).PrivPin[:], digest)
			key.(*keymanage.MemStorSM2Key).PrivKeyAuth = 1
		}

	} else if keytype == uint32(keymanage.RSA_TYPE_FLAG) {
		rpubk, rpivk, uiret := ISDF.GenerateKeyPairRSA(MSSesH, int(keybits))
		if uiret != 0 {
			sendErrorMsgBack(conn, uiret)
			return b.CreateStdErr(int(uiret),
				"GenKey Error ret : %08X", uiret)
		}
		key = &keymanage.MemStorRSAKey{}
		key.(*keymanage.MemStorRSAKey).Idx = int(keyidx)
		key.(*keymanage.MemStorRSAKey).PubKey = *rpubk
		key.(*keymanage.MemStorRSAKey).PrivKey = *rpivk
		if len(msg) > 12 {
			digest, uiret := ISDF.Hash(MSSesH, msg[12:])
			if uiret != 0 {
				sendErrorMsgBack(conn, uiret)
				return b.CreateStdErr(int(uiret),
					"GenKey Error ret : %08X", uiret)
			}
			copy(key.(*keymanage.MemStorRSAKey).PrivPin[:], digest)
			key.(*keymanage.MemStorRSAKey).PrivKeyAuth = 1
		}
	}

	stderr := keymanage.AddKey2SQL(MSSesH, key, MRootKey)
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 通知密码服务
	stderr = callCryptoServer_GenKey(int(keytype), int(keyidx))
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	sendmsglen := 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 2.删除密钥
// 0xB002
// rcv msg : keytype[0-4] keyidx[4-8]
// snd msg :
func mDelKey(conn net.Conn, msg []byte) *b.StdErr {
	if MDevInitedFlag != 1 {
		sendErrorMsgBack(conn, b.DEV_NOT_INITED)
		return b.CreateStdErr(int(b.DEV_NOT_INITED),
			"GenKey Error Device Has Not Initialized")
	}

	keytype := binary.BigEndian.Uint32(msg[0:])
	keyidx := binary.BigEndian.Uint32(msg[4:])

	stderr := keymanage.DelKeyFromSQL(int(keyidx), int(keytype))
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 通知密码服务
	stderr = callCryptoServer_DelKey(int(keytype), int(keyidx))
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	sendmsglen := 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil

}

// 3.设置/重置私钥授权码
// 0xB003
// rcv msg : keytype[0-4] keyidx[4-8] keypin[8-]
// snd msg :
func mSetPrivKPin(conn net.Conn, msg []byte) *b.StdErr {
	if MDevInitedFlag != 1 {
		sendErrorMsgBack(conn, b.DEV_NOT_INITED)
		return b.CreateStdErr(int(b.DEV_NOT_INITED),
			"GenKey Error Device Has Not Initialized")
	}

	keytype := binary.BigEndian.Uint32(msg[0:])
	keyidx := binary.BigEndian.Uint32(msg[4:])
	var keypin []byte
	if len(msg) == 8 {
		keypin = nil
	} else {
		keypin = msg[8:]
	}

	stderr := keymanage.SetPivKPinInSQL(MSSesH, int(keyidx), int(keytype), keypin)
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 通知密码服务
	stderr = callCryptoServer_SetPrivKPin(int(keytype), int(keyidx))
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	sendmsglen := 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 4.创建用户
// 0xB004				   name_or_uuid(0:name 1:uuid)
// rcv msg : usertype[0-4] name_or_uuid[4-8] uuid[8-8+32] pinLen[8+uuidLen-12+uuidLen] pin[12+uuidLen-16+uuidLen] pubk[16+uuidLen-]
// snd msg :
func mCreateUser(conn net.Conn, msg []byte) *b.StdErr {
	var pubk ISDF.ECCrefPublicKey
	var offset uint32 = 0
	usertype := binary.BigEndian.Uint32(msg[offset:])
	offset += 4

	name_or_uuid := binary.BigEndian.Uint32(msg[offset:])
	offset += 4
	if name_or_uuid == 1 {
		uuid := msg[offset : offset+32]
		offset += 32
		pinLen := binary.BigEndian.Uint32(msg[offset:])
		offset += 4
		pin := msg[offset : offset+pinLen]
		offset += pinLen

		pubk.Bits = uint(binary.BigEndian.Uint32(msg[offset:]))
		offset += 4
		pubk.X = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[offset]))
		offset += uint32(ISDF.ECCref_MAX_LEN)
		pubk.Y = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[offset]))
		offset += uint32(ISDF.ECCref_MAX_LEN)

		stderr := usermanage.CreateUser(MSSesH, int(usertype), nil, uuid, pin, &pubk)
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
	} else {
		name := msg[offset : offset+32]
		offset += 32
		pinLen := binary.BigEndian.Uint32(msg[offset:])
		offset += 4
		pin := msg[offset : offset+pinLen]
		offset += pinLen

		stderr := usermanage.CreateUser(MSSesH, int(usertype), name, nil, pin, nil)
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
	}

	// 返回界面正确结果
	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)

	return nil
}

// 5.删除用户
// 0xB005
// rcv msg : name_or_uuid[0-4] uuid[4-36]
// snd msg :
func mDelUser(conn net.Conn, msg []byte) *b.StdErr {
	var offset = 0
	name_or_uuid := binary.BigEndian.Uint32(msg[offset:])
	offset += 4
	if name_or_uuid == 1 {
		stderr := usermanage.DelUser(nil, msg[offset:offset+32])
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
	} else {
		stderr := usermanage.DelUser(msg[offset:offset+32], nil)
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
	}
	// 返回界面正确结果
	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 6.用户验证
// 0xB006
// rcv msg : name_or_uuid[0-4] uuid[4-4+32] pinlen[36-40] pin[40-40+pinlen] random[40+pinlen-56+pinlen] ecsig[-]
// snd msg :
func mVerifyUser(conn net.Conn, msg []byte) *b.StdErr {
	var ecsig ISDF.ECCSignature
	var offset = 0
	name_or_uuid := binary.BigEndian.Uint32(msg[offset:])
	offset += 4
	idf := msg[offset : offset+32]
	offset += 32
	pinlen := binary.BigEndian.Uint32(msg[offset:])
	offset += 4
	pin := msg[offset : offset+int(pinlen)]
	offset += int(pinlen)

	var userType int
	if name_or_uuid == 1 {
		random := msg[offset : offset+16]
		offset += 16
		ecsig.R = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[offset]))
		offset += 64
		ecsig.S = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[offset]))
		offset += 64

		usertype, stderr := usermanage.UserVerify(MSSesH, nil, idf, pin, random, &ecsig)
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
		userType = usertype
	} else {
		usertype, stderr := usermanage.UserVerify(MSSesH, idf, nil, pin, nil, nil)
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
		userType = usertype
	}

	// 返回界面正确结果
	var sendmsglen = 8 + 4
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	binary.BigEndian.PutUint32(sendmsg[8:], uint32(userType))
	conn.Write(sendmsg)
	return nil
}

// 7.设备初始化状态
// 0xB007
// rcv msg :
// snd msg :
func mIfDevInited(conn net.Conn, msg []byte) *b.StdErr {
	// 返回界面正确结果
	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(MDevInitedFlag))
	conn.Write(sendmsg)
	return nil
}

// 8.生成主密钥
// 0xB008
// rcv msg :
// snd msg :
func mGenRootKey(conn net.Conn, msg []byte) *b.StdErr {
	stderr := initialize.GenRootKey(MSSesH)
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 9.设置初始化成功状态
// 0xB009
// rcv msg :
// snd msg :
func mSetDevInited(conn net.Conn, msg []byte) *b.StdErr {
	stderr := keymanage.SqlSetDevInited()
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 10.获取用户列表
// 0xB00A
// rcv msg :
// snd msg : type len uuid
func mGetCurrentUserList(conn net.Conn, msg []byte) *b.StdErr {
	userList, stderr := usermanage.GetUserList()
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	var i int = 0
	var listLen int
	var listMsg = make([]byte, 2048)
	for i = 0; i < len(userList); i++ {
		usertype := userList[i].UserType
		uuidlen := len(userList[i].UserUUID)
		binary.BigEndian.PutUint32(listMsg[listLen:], uint32(usertype))
		listLen += 4
		binary.BigEndian.PutUint32(listMsg[listLen:], uint32(uuidlen))
		listLen += 4
		copy(listMsg[listLen:], userList[i].UserUUID)
		listLen += uuidlen
	}
	var sendmsglen = 8 + listLen
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	copy(sendmsg[8:], listMsg[:listLen])
	conn.Write(sendmsg)
	return nil
}

// 11.获取密钥列表
// 0xB00B
// rcv msg : keytype[0-4]
// snd msg :
func mGetCurrentKeyList(conn net.Conn, msg []byte) *b.StdErr {
	keytype := binary.BigEndian.Uint32(msg[0:])

	keyList, stderr := keymanage.GetKeyListFromSQL(int(keytype))
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	var i int = 0
	var listLen int
	var listMsg = make([]byte, 20480)
	for i = 0; i < len(keyList); i++ {
		binary.BigEndian.PutUint32(listMsg[listLen:], uint32(keyList[i]))
		listLen += 4
	}
	var sendmsglen = 8 + listLen
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	copy(sendmsg[8:], listMsg[:listLen])
	conn.Write(sendmsg)
	return nil
}

// 12.密钥拆分
// 0xB00C
// rcv msg : divtype[0-4] keyidx[4-8] keytype[8-12] sigORenc[12-16]
// snd msg :
func mKeyDiv(conn net.Conn, msg []byte) *b.StdErr {
	divtype := binary.BigEndian.Uint32(msg[0:])
	keyidx := binary.BigEndian.Uint32(msg[4:])
	keytype := binary.BigEndian.Uint32(msg[8:])
	sigORenc := binary.BigEndian.Uint32(msg[12:])
	if sigORenc == 1 {
		keyidx = keyidx*2 - 1
	} else if sigORenc == 2 {
		keyidx = keyidx * 2
	} else {
		stderr := b.CreateStdErr(-1, "Key Div Error ret : %08X", -1)
		sendErrorMsgBack(conn, stderr.Errcode)
		return stderr
	}

	if divtype == 0 {
		s, stderr := keymanage.KeyDiv32(MSSesH, int(keyidx), byte(keytype), MRootKey)
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
		var sendmsglen = 8 + 4 + len(s[0]) + 4 + len(s[1]) + 4 + len(s[2])
		var sendmsg = make([]byte, sendmsglen)
		binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
		binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
		binary.BigEndian.PutUint32(sendmsg[8:], uint32(len(s[0])))
		copy(sendmsg[12:], s[0])
		binary.BigEndian.PutUint32(sendmsg[12+len(s[0]):], uint32(len(s[1])))
		copy(sendmsg[16+len(s[0]):], s[1])
		binary.BigEndian.PutUint32(sendmsg[16+len(s[0])+len(s[1]):], uint32(len(s[2])))
		copy(sendmsg[20+len(s[0])+len(s[1]):], s[2])
		conn.Write(sendmsg)
	} else {
		s, stderr := keymanage.KeyDiv53(MSSesH, int(keyidx), byte(keytype), MRootKey)
		if stderr != nil {
			sendErrorMsgBack(conn, int(stderr.Errcode))
			return stderr
		}
		var sendmsglen = 8 + 4 + len(s[0]) + 4 + len(s[1]) + 4 + len(s[2]) + 4 + len(s[3]) + 4 + len(s[4])
		var sendmsg = make([]byte, sendmsglen)
		binary.BigEndian.PutUint32(sendmsg, uint32(sendmsglen))
		binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
		binary.BigEndian.PutUint32(sendmsg[8:], uint32(len(s[0])))
		copy(sendmsg[12:], s[0])
		binary.BigEndian.PutUint32(sendmsg[12+len(s[0]):], uint32(len(s[1])))
		copy(sendmsg[16+len(s[0]):], s[1])
		binary.BigEndian.PutUint32(sendmsg[16+len(s[0])+len(s[1]):], uint32(len(s[2])))
		copy(sendmsg[20+len(s[0])+len(s[1]):], s[2])
		binary.BigEndian.PutUint32(sendmsg[20+len(s[0])+len(s[1])+len(s[2]):], uint32(len(s[3])))
		copy(sendmsg[24+len(s[0])+len(s[1])+len(s[2]):], s[3])
		binary.BigEndian.PutUint32(sendmsg[20+len(s[0])+len(s[1])+len(s[2])+len(s[3]):], uint32(len(s[4])))
		copy(sendmsg[28+len(s[0])+len(s[1])+len(s[2])+len(s[3]):], s[4])
		conn.Write(sendmsg)
	}

	return nil
}

// 13.密钥恢复
// 0xB00D
// rcv msg : cbtype[0-4] msg1Len [4-8] msg1[8-8+nsg1Len] msg2Len ...
// snd msg :
func mKeyComeBack(conn net.Conn, msg []byte) *b.StdErr {
	var stderr *b.StdErr
	cbtype := binary.BigEndian.Uint32(msg[0:])
	msg1Len := binary.BigEndian.Uint32(msg[4:])
	msg1 := msg[8 : 8+msg1Len]
	msg2Len := binary.BigEndian.Uint32(msg[8+msg1Len:])
	msg2 := msg[12+msg1Len : 12+msg1Len+msg2Len]

	if cbtype == 0 {
		stderr = keymanage.KeyComeBack32(MSSesH, msg1, msg2, MRootKey)
	} else {
		msg3Len := binary.BigEndian.Uint32(msg[12+msg1Len+msg2Len:])
		msg3 := msg[16+msg1Len+msg2Len : 16+msg1Len+msg2Len+msg3Len]
		stderr = keymanage.KeyComeBack53(MSSesH, msg1, msg2, msg3, MRootKey)
	}
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}
	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 14.重启服务
// 0xB00E
// rcv msg :
// snd msg :
func mRestartMserver(conn net.Conn, msg []byte) *b.StdErr {
	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	time.Sleep(1 * time.Second)
	fmt.Println("saved mRestartMserver")
	callCryptoServer_Restart()
	time.Sleep(1 * time.Second)

	b.Restart()
	return nil
}

// 15.恢复出厂设置
// 0xB00F
// rcv msg :
// snd msg :
func mResetAll(conn net.Conn, msg []byte) *b.StdErr {
	keyisd_name := "./kek-1.key"
	dir_name := "../CreatedFile"

	sqlop.SqlDestroy()
	err := os.Remove(keyisd_name)
	// if err != nil {
	// 	sendErrorMsgBack(conn, int(b.UNALBE_DEL_DEPENDENCIES))
	// 	return b.CreateStdErr(b.UNALBE_DEL_DEPENDENCIES, "Reset Error Unable To Delete Dependencies")
	// }
	err = os.RemoveAll(dir_name)
	if err != nil {
		sendErrorMsgBack(conn, int(b.UNALBE_DEL_DEPENDENCIES))
		return b.CreateStdErr(b.UNALBE_DEL_DEPENDENCIES, "Reset Error Unable To Delete Dependencies")
	}
	err = os.Mkdir(dir_name, 0755)
	if err != nil {
		sendErrorMsgBack(conn, int(b.UNALBE_DEL_DEPENDENCIES))
		return b.CreateStdErr(b.UNALBE_DEL_DEPENDENCIES, "Reset Error Unable To Delete Dependencies")
	}
	stderr := sqlop.SqlCreate()
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)

	b.Restart()
	return nil
}

// 16.算法正确性自检
// 0xB010
// rcv msg :flag[0-1]
// snd msg :
func mDevSelfCheck(conn net.Conn, msg []byte) *b.StdErr {
	flag := msg[0]
	stderr := initialize.AlgCorrectnessCheck(MSSesH, flag)
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	var sendmsglen = 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 17.获取设备信息
// 0xB011
// rcv msg :
// snd msg : devinfo[0-40 + 16 + 16 + 4 + 4 + 4*2 + 4 + 4 + 4]
func mGetDevInfo(conn net.Conn, msg []byte) *b.StdErr {
	devinfo, uiret := ISDF.GetDeviceInfo(MSSesH)
	if uiret != 0 {
		sendErrorMsgBack(conn, uiret)
		return b.CreateStdErr(int(uiret),
			"Get DevInfo error ret : %08X", uiret)
	}

	var sendmsglen = 8 + 40 + 16 + 16 + 4 + 4 + 4*2 + 4 + 4 + 4
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	var offset = 8
	copy(sendmsg[offset:], devinfo.IssuerName[:])
	offset += 40
	copy(sendmsg[offset:], devinfo.DeviceName[:])
	offset += 16
	copy(sendmsg[offset:], devinfo.DeviceSerial[:])
	offset += 16
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(devinfo.DeviceVersion))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(devinfo.StandardVersion))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(devinfo.AsymAlgAbility[0]))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(devinfo.AsymAlgAbility[1]))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(devinfo.SymAlgAbility))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(devinfo.HashAlgAbility))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(devinfo.BufferSize))
	offset += 4
	conn.Write(sendmsg)
	return nil
}

// 18.获取系统运行信息
// 0xB012
// rcv msg :
// snd msg : sysinfo[0-8 + 4 + 4 + 4]
func mGetSysStatus(conn net.Conn, msg []byte) *b.StdErr {
	sysinfo, stderr := b.GetSystemStats()
	if stderr != nil {
		sendErrorMsgBack(conn, stderr.Errcode)
		return stderr
	}

	var sendmsglen = 8 + 4 + 4 + 4
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	var offset = 8
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(sysinfo.Uptime))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(sysinfo.CPUUsage))
	offset += 4
	binary.BigEndian.PutUint32(sendmsg[offset:], uint32(sysinfo.MemoryUsage))
	offset += 4
	conn.Write(sendmsg)
	return nil
}

// 18.获取网卡信息
// 0xB013
// rcv msg : ip_type[0](0:IPV4,1:IPV6)
// snd msg : sysinfo[0-8 + 32*itf_nums]
func mGetIntfInfo(conn net.Conn, msg []byte) *b.StdErr {
	if msg[0] == 0x00 {
		interface_info, stderr := b.GetIPV4NetworkConfig()
		if stderr != nil {
			sendErrorMsgBack(conn, stderr.Errcode)
			return stderr
		}

		interface_nums := len(interface_info)

		var sendmsglen = 8 + interface_nums*(16+4+4+4+4)
		var sendmsg = make([]byte, sendmsglen)
		binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
		binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
		var offset = 8
		var i int
		for i = 0; i < interface_nums; i++ {
			copy(sendmsg[offset:], interface_info[i].Name[:])
			offset += 16
			copy(sendmsg[offset:], interface_info[i].IP[:])
			offset += 4
			copy(sendmsg[offset:], interface_info[i].Gateway[:])
			offset += 4
			copy(sendmsg[offset:], interface_info[i].Netmask[:])
			offset += 4
			binary.BigEndian.PutUint32(sendmsg[offset:], uint32(interface_info[i].IsActive))
			offset += 4
		}
		conn.Write(sendmsg)
	} else if msg[0] == 0x01 {
		var UNSUPPORT_IPV6 = 0xE123E123
		// 暂不支持IPV6
		sendErrorMsgBack(conn, UNSUPPORT_IPV6)
	} else {
		sendErrorMsgBack(conn, b.UNKNOW_IPTYPE)
	}
	return nil
}

// 19.修改网卡信息
// 0xB014
// rcv msg : ip_type[0](0:IPV4,1:IPV6) itf_name[1-17] itf_IP[17-21] itf_gateway[21-25] itf_netmask[25-29]
// snd msg :
func bytesToIPv4Str(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		return ""
	}

	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func mModifyItfInfo(conn net.Conn, msg []byte) *b.StdErr {
	if msg[0] == 0x00 {
		itf_name := string(bytes.TrimRight(msg[1:17], "\x00"))
		itf_IP := msg[17:21]
		itf_gateway := msg[21:25]
		itf_netmask := msg[25:29]

		// 转换处理
		str_itf_ip := bytesToIPv4Str(itf_IP)
		str_itf_gateway := bytesToIPv4Str(itf_gateway)
		str_itf_netmask := bytesToIPv4Str(itf_netmask)

		stderr := b.ModifyIPV4NetworkConfig(itf_name, str_itf_ip, str_itf_gateway, str_itf_netmask)
		if stderr != nil {
			sendErrorMsgBack(conn, stderr.Errcode)
			return stderr
		}

		var sendmsglen = 8
		var sendmsg = make([]byte, sendmsglen)
		binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
		binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
		conn.Write(sendmsg)
	} else if msg[0] == 0x01 {
		var UNSUPPORT_IPV6 = 0xE123E123
		// 暂不支持IPV6
		sendErrorMsgBack(conn, UNSUPPORT_IPV6)
	} else {
		sendErrorMsgBack(conn, b.UNKNOW_IPTYPE)
	}
	return nil
}

// 20.添加白名单
// 0xB015
// rcv msg : ip[0-]
// snd msg :
func mAddWhiteTable(conn net.Conn, msg []byte) *b.StdErr {
	ip := msg[:]
	stderr := w.AddCIDR2IPNets(string(ip))
	if stderr != nil {
		sendErrorMsgBack(conn, stderr.Errcode)
		return stderr
	}

	// 通知密码服务
	stderr = callCryptoServer_UpdateWhiteTable()
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	sendmsglen := 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 21.删除白名单
// 0xB016
// rcv msg : ip[0-]
// snd msg :
func mDelWhiteTable(conn net.Conn, msg []byte) *b.StdErr {
	ip := msg[:]
	stderr := w.DelCIDRFromIPNets(string(ip))
	if stderr != nil {
		sendErrorMsgBack(conn, stderr.Errcode)
		return stderr
	}

	// 通知密码服务
	stderr = callCryptoServer_UpdateWhiteTable()
	if stderr != nil {
		sendErrorMsgBack(conn, int(stderr.Errcode))
		return stderr
	}

	// 返回界面正确结果
	sendmsglen := 8
	var sendmsg = make([]byte, sendmsglen)
	binary.BigEndian.PutUint32(sendmsg[0:], uint32(sendmsglen))
	binary.BigEndian.PutUint32(sendmsg[4:], uint32(0))
	conn.Write(sendmsg)
	return nil
}

// 22.解析Der编码证书
// 0xB016
// rcv msg : ip[0-]
// snd msg :
