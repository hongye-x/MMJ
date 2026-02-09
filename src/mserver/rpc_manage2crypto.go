package main

import (
	"net"
	b "sig_vfy/src/base"
	"strings"
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
	// 重试机制
	maxRetries := 2
	for attempt := 0; attempt < maxRetries; attempt++ {
		client, err := getRPCClient()
		if err != nil {
			if attempt == maxRetries-1 {
				return b.CreateStdErr(b.RPC_REGORCALL_ERROR,
					"Failed to get client: %v", err)
			}
			continue
		}

		var ret int
		err = client.Call(fname, args, &ret)
		if err == nil && ret == 0 {
			return nil
		}

		// 调用失败，如果是连接错误，清理客户端以便下次重试
		if isConnectionError(err) {
			clientMu.Lock()
			if cryptoClient == client {
				cryptoClient.Close()
				cryptoClient = nil
			}
			clientMu.Unlock()
		}

		if attempt == maxRetries-1 {
			return b.CreateStdErr(b.RPC_REGORCALL_ERROR,
				"%s failed: %v", fname, err)
		}
	}

	return b.CreateStdErr(b.RPC_REGORCALL_ERROR,
		"Max retries exceeded for %s", fname)
}

// 判断是否是连接错误
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// 常见的连接错误关键字
	connectionErrors := []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"io timeout",
		"EOF",
		"use of closed network connection",
		"dial unix",
		"no such file or directory", // socket文件不存在
		"network is unreachable",
		"transport is closing",
		"rpc: client protocol error",
	}

	// 转换为小写进行比较
	lowerErr := strings.ToLower(errStr)
	for _, connErr := range connectionErrors {
		if strings.Contains(lowerErr, connErr) {
			return true
		}
	}

	return false
}

func recreateConnection() net.Conn {
	// 重新创建连接的逻辑
	conn, err := net.Dial("unix", "/var/run/crypto_server.sock")
	if err != nil {
		return nil
	}
	return conn
}

func callCryptoServer_GenKey(KeyType int, KeyIdx int) *b.StdErr {
	kop := &KeyOperArgs{KeyType, KeyIdx}
	return mSendRecvCryServer("KeyOper.MInformGenKey", kop)
}

func callCryptoServer_DelKey(KeyType int, KeyIdx int) *b.StdErr {
	kop := &KeyOperArgs{KeyType, KeyIdx}
	return mSendRecvCryServer("KeyOper.MInformDelKey", kop)
}

func callCryptoServer_SetPrivKPin(KeyType int, KeyIdx int) *b.StdErr {
	kop := &KeyOperArgs{KeyType, KeyIdx}
	return mSendRecvCryServer("KeyOper.MInformSetPrivKPin", kop)
}

func callCryptoServer_UpdateWhiteTable() *b.StdErr {
	dm := &DevMangArgs{}
	return mSendRecvCryServer("DevMang.MInformUpdateWhiteTable", dm)
}

func callCryptoServer_Restart() *b.StdErr {
	dm := &DevMangArgs{}
	return mSendRecvCryServer("DevMang.MRestart", dm)
}
