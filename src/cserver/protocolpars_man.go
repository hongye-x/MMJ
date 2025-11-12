package main

import (
	"net/rpc"
	"sig_vfy/src/keymanage"
	"sig_vfy/src/whitetable"
)

var rpcs = []any{
	new(KeyOper),
	new(DevMang),
}

func rpcRegister() error {
	for _, s := range rpcs {
		err := rpc.Register(s)
		if err != nil {
			return err
		}
	}
	return nil
}

// ===============设备管理类函数===============
type DevMang struct{}
type DevMangArgs struct {
}

func (dm *DevMang) MInformUpdateWhiteTable(args *DevMangArgs, ret *int) error {
	*ret = 0
	stderr := whitetable.LoadIPNetsFromDB()
	if stderr != nil {
		*ret = stderr.Errcode
	}
	return nil
}

// ===============密钥操作类函数===============
type KeyOper struct{}

type KeyOperArgs struct {
	KeyType int
	KeyIdx  int
}

func (kop *KeyOper) MInformGenKey(args *KeyOperArgs, ret *int) error {
	*ret = 0
	keyV, _, stderr := keymanage.GetKeyValueFromSQL(CSSesH, args.KeyIdx, args.KeyType, CRootKey)
	if stderr != nil {
		*ret = stderr.Errcode
		return nil
	}
	keymanage.AddKey2Map(keyV)
	return nil
}

func (kop *KeyOper) MInformDelKey(args *KeyOperArgs, ret *int) error {
	*ret = 0
	err := keymanage.DelKeyFromMap(args.KeyIdx, args.KeyType)
	if err != nil {
		*ret = err.Errcode
	}
	return nil
}

func (kop *KeyOper) MInformSetPrivKPin(args *KeyOperArgs, ret *int) error {
	*ret = 0
	keymanage.DelKeyFromMap(args.KeyIdx, args.KeyType)
	keyV, _, stderr := keymanage.GetKeyValueFromSQL(CSSesH, args.KeyIdx, args.KeyType, CRootKey)
	if stderr != nil {
		*ret = stderr.Errcode
		return nil
	}
	keymanage.AddKey2Map(keyV)
	return nil
}

// func ParsManageMsgAndSend(conn net.Conn) {
// 	var msg = make([]byte, 8)
// 	reader := bufio.NewReader(conn)
// 	for {
// 		rdlen, err := reader.Read(msg)
// 		if err != nil {
// 			conn.Close()
// 			return
// 		}
// 		if rdlen < 8 {
// 			return
// 		}

// 		var offset int = 0
// 		var totalLen int
// 		var cmd int
// 		totalLen = int(binary.BigEndian.Uint32(msg[offset : offset+4]))
// 		offset += 4
// 		cmd = int(binary.BigEndian.Uint32(msg[offset : offset+4]))
// 		offset += 4

// 		var msgbody = make([]byte, totalLen-8)
// 		_, err = reader.Read(msgbody)
// 		if err != nil {
// 			conn.Close()
// 			return
// 		}

// 		switch cmd {
// 		case 0xB001:
// 			stderr := mInformGenKey(conn, msgbody)
// 			if stderr != nil {
// 				b.PrintStdErr(stderr)
// 			}

// 		case 0xB002:
// 			stderr := mInformDelKey(conn, msgbody)
// 			if stderr != nil {
// 				b.PrintStdErr(stderr)
// 			}

// 		case 0xB003:
// 			stderr := mInformSetPrivKPin(conn, msgbody)
// 			if stderr != nil {
// 				b.PrintStdErr(stderr)
// 			}

// 		}
// 	}
// }

// // 1. 生成密钥
// // 0xB001
// // rcv msg : keytype[0-4] keyidx[4-8]
// // snd msg :
// func mInformGenKey(conn net.Conn, msg []byte) *b.StdErr {
// 	keytype := binary.BigEndian.Uint32(msg[0:])
// 	keyidx := binary.BigEndian.Uint32(msg[4:])

// 	keyV, _, stderr := keymanage.GetKeyValueFromSQL(CSSesH, int(keyidx), int(keytype), CRootKey)
// 	if stderr != nil {
// 		sendErrorMsgBack(conn, uint(stderr.Errcode))
// 		return stderr
// 	}
// 	keymanage.AddKey2Map(keyV)

// 	len := 8
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
// 	conn.Write(rtmsg)
// 	return nil
// }

// // 2.删除密钥
// // 0xB002
// // rcv msg : keytype[0-4] keyidx[4-8]
// // snd msg :
// func mInformDelKey(conn net.Conn, msg []byte) *b.StdErr {
// 	keytype := binary.BigEndian.Uint32(msg[0:])
// 	keyidx := binary.BigEndian.Uint32(msg[4:])

// 	keymanage.DelKeyFromMap(int(keyidx), int(keytype))

// 	len := 8
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
// 	conn.Write(rtmsg)
// 	return nil
// }

// // 3.设置/重置私钥授权码
// // 0xB003
// // rcv msg : keytype[0-4] keyidx[4-8]
// // snd msg :
// func mInformSetPrivKPin(conn net.Conn, msg []byte) *b.StdErr {
// 	keytype := binary.BigEndian.Uint32(msg[0:])
// 	keyidx := binary.BigEndian.Uint32(msg[4:])

// 	keymanage.DelKeyFromMap(int(keyidx), int(keytype))
// 	keyV, _, stderr := keymanage.GetKeyValueFromSQL(CSSesH, int(keyidx), int(keytype), CRootKey)
// 	if stderr != nil {
// 		sendErrorMsgBack(conn, uint(stderr.Errcode))
// 		return stderr
// 	}

// 	keymanage.AddKey2Map(keyV)

// 	len := 8
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
// 	conn.Write(rtmsg)
// 	return nil
// }

// // 4.更新白名单
// // 0xB004
// // rcv msg :
// // snd msg :
// func mInformUpdateWhiteTable(conn net.Conn, msg []byte) *b.StdErr {
// 	stderr := whitetable.LoadIPNetsFromDB()
// 	if stderr != nil {
// 		sendErrorMsgBack(conn, uint(stderr.Errcode))
// 		return stderr
// 	}

// 	len := 8
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
// 	conn.Write(rtmsg)
// 	return nil
// }
