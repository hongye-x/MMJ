package main

import (
	"net/rpc"
	b "sig_vfy/src/base"
)

// ===============设备管理类函数===============
type DevMang struct{}

type DevMangArgs struct {
}

// ===============密钥操作类函数===============
type KeyOper struct{}

type KeyOperArgs struct {
	KeyType int
	KeyIdx  int
}

type OperRet struct {
	RetCode int
}

func mSendRecvCryServer(fname string, args any) *b.StdErr {
	if GLinuxSock == nil {
		return nil
	}
	client := rpc.NewClient(GLinuxSock)
	var ret int = -1
	err := client.Call(fname, args, &ret)
	if err != nil {
		return b.CreateStdErr(b.RPC_REGORCALL_ERROR,
			"%s Rpc Call Error Code[%08X]", fname, b.RPC_REGORCALL_ERROR)
	}
	if ret != 0 {
		return b.CreateStdErr(ret,
			"%s Error Code[%08X]", fname, ret)
	}
	return nil
}

// 通知密码服务生成密钥
func callCryptoServer_GenKey(KeyType int, KeyIdx int) *b.StdErr {
	kop := &KeyOperArgs{KeyType, KeyIdx}
	return mSendRecvCryServer("KeyOper.MInformGenKey", kop)
}

// 通知密码服务删除密钥
func callCryptoServer_DelKey(KeyType int, KeyIdx int) *b.StdErr {
	kop := &KeyOperArgs{KeyType, KeyIdx}
	return mSendRecvCryServer("KeyOper.MInformDelKey", kop)
}

// 通知密码服务更新私钥授权码
func callCryptoServer_SetPrivKPin(KeyType int, KeyIdx int) *b.StdErr {
	kop := &KeyOperArgs{KeyType, KeyIdx}
	return mSendRecvCryServer("KeyOper.MInformSetPrivKPin", kop)
}

// 通知密码服务更新白名单
func callCryptoServer_UpdateWhiteTable() *b.StdErr {
	dm := &DevMangArgs{}
	return mSendRecvCryServer("KeyOper.MInformUpdateWhiteTable", dm)
}
