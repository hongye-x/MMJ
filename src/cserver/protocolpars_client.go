package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	slog "sig_vfy/src/log"
	"time"
	"unsafe"
)

func sendErrorMsgBack(conn net.Conn, uiret uint) {
	rtmsg := make([]byte, 8)
	binary.BigEndian.PutUint32(rtmsg, uint32(8))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	if conn != nil {
		conn.Write(rtmsg)
	}
}

func GetRSAPubKeyFromMsg(msg []byte) *ISDF.RSArefPublicKey {
	var rpubk ISDF.RSArefPublicKey
	rpubk.Bits = uint(binary.BigEndian.Uint32(msg[:]))
	rpubk.M = *(*[ISDF.LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&msg[4]))
	rpubk.E = *(*[ISDF.LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN]))
	return &rpubk
}

func GetRSAPivKeyFromMsg(msg []byte) *ISDF.RSArefPrivateKey {
	var rpivk ISDF.RSArefPrivateKey
	rpivk.Bits = uint(binary.BigEndian.Uint32(msg[:]))
	rpivk.M = *(*[ISDF.LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&msg[4]))
	rpivk.E = *(*[ISDF.LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN]))
	rpivk.D = *(*[ISDF.LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN*2]))
	rpivk.Prime[0] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN*3]))
	rpivk.Prime[1] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN*3+ISDF.LiteRSAref_MAX_PLEN]))
	rpivk.Pexp[0] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN*4]))
	rpivk.Pexp[1] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN*4+ISDF.LiteRSAref_MAX_PLEN]))
	rpivk.Coef = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&msg[4+ISDF.LiteRSAref_MAX_LEN*5]))
	return &rpivk
}

func GetECCPubKeyFromMsg(msg []byte) *ISDF.ECCrefPublicKey {
	var epubk ISDF.ECCrefPublicKey
	epubk.Bits = uint(binary.BigEndian.Uint32(msg[:]))
	epubk.X = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[4]))
	epubk.Y = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[4+ISDF.ECCref_MAX_LEN]))
	return &epubk
}

func GetECCPivKeyFromMsg(msg []byte) *ISDF.ECCrefPrivateKey {
	var epivk ISDF.ECCrefPrivateKey
	epivk.Bits = uint(binary.BigEndian.Uint32(msg[:]))
	epivk.K = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[4]))
	return &epivk
}

func GetECCCipherFromMsg(msg []byte) *ISDF.ECCCipher {
	var ecip ISDF.ECCCipher
	ecip.X = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[0]))
	ecip.Y = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[ISDF.ECCref_MAX_LEN]))
	ecip.M = *(*[32]byte)(unsafe.Pointer(&msg[ISDF.ECCref_MAX_LEN*2]))
	ecip.C = *(*[ISDF.ECCref_CIPHER_LEN]byte)(unsafe.Pointer(&msg[ISDF.ECCref_MAX_LEN*2+36]))
	ecip.L = uint(binary.BigEndian.Uint32(msg[ISDF.ECCref_MAX_LEN*2+32:]))

	return &ecip
}

func GetECCSigFromMsg(msg []byte) *ISDF.ECCSignature {
	var ecsig ISDF.ECCSignature
	ecsig.R = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[0]))
	ecsig.S = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&msg[ISDF.ECCref_MAX_LEN]))
	return &ecsig
}

func ParsClientMsgAndSend_MMJ(conn net.Conn) *b.StdErr {
	timeoutDuration := 5 * time.Second //5s
	conn.SetDeadline(time.Now().Add(timeoutDuration))

	var msg = make([]byte, 8)
	reader := bufio.NewReader(conn)
	for {
		rdlen, err := reader.Read(msg)
		if err != nil {
			conn.Close()
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
		var msgbody = make([]byte, totalLen-8)
		_, err = reader.Read(msgbody)
		if err != nil {
			conn.Close()
			return nil
		}
		connip := conn.RemoteAddr().String()

		switch cmd {
		case 0x5001:
			stderr := sDevOpen(conn)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_OpenDevice Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_OpenDevice Success")
			}

		case 0x5002:
			stderr := sDevClose(conn)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_CloseDevice Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_CloseDevice Success")
			}

		case 0x5003:
			stderr := sSesOpen(conn)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_OpenSession Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_OpenSession Success")
			}

		case 0x5004:
			stderr := sSesClose(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_OpenSession Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_OpenSession Success")
			}
			conn.Close()
			RWmu.Lock()
			CrySerStatus.ConnNums--
			RWmu.Unlock()

		case 0x5005:
			stderr := sGetDevInf(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GetDeviceInfo Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GetDeviceInfo Success")
			}

		case 0x5006:
			stderr := sGenRand(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateRandom Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateRandom Success")
			}

		case 0x5007:
			stderr := sGetPrivKeyAccessRight(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GetPrivateKeyAccessRight Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GetPrivateKeyAccessRight Success")
			}

		case 0x5008:
			stderr := sReleasePrivKeyAccessRight(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ReleasePrivateKeyAccessRight Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ReleasePrivateKeyAccessRight Success")
			}

		case 0x6001:
			stderr := sExportRsaSigPubKey(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExportSignPublicKey_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExportSignPublicKey_RSA Success")
			}

		case 0x6002:
			stderr := sExportRsaEncPubKey(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExportEncPublicKey_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExportEncPublicKey_RSA Success")
			}
		case 0x6003:
			stderr := sGenRsaKeyPair(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateKeyPair_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateKeyPair_RSA Success")
			}

		case 0x6004:
			stderr := sGenKeyWithIPKRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateKeyWithIPK_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateKeyWithIPK_RSA Success")
			}

		case 0x6005:
			stderr := sGenKeyWithEPKRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateKeyWithEPK_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateKeyWithEPK_RSA Success")
			}

		case 0x6006:
			stderr := sImpKeyWithISKRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ImportKeyWithISK_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ImportKeyWithISK_RSA Success")
			}

		case 0x6007:
			stderr := sExchangeDigEnvRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExchangeDigitEnvelopeBaseOnRSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExchangeDigitEnvelopeBaseOnRSA Success")
			}

		case 0x6008:
			stderr := sExportEccSigKey(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExportSignPublicKey_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExportSignPublicKey_ECC Success")
			}

		case 0x6009:
			stderr := sExportEccEncKey(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExportEncPublicKey_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExportEncPublicKey_ECC Success")
			}

		case 0x600A:
			stderr := sGenEccKeyPair(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateKeyPair_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateKeyPair_ECC Success")
			}

		case 0x600B:
			stderr := sGenKeyWithIPKEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateKeyWithIPK_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateKeyWithIPK_ECC Success")
			}

		case 0x600C:
			stderr := sGenKeyWithEPKEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateKeyWithEPK_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateKeyWithEPK_ECC Success")
			}

		case 0x600D:
			stderr := sImpKeyWithISKEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ImportKeyWithISK_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ImportKeyWithISK_ECC Success")
			}

		// case 0x600E:
		// 	stderr := sExchangeDigEnvRsa(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}
		// case 0x600F:
		// 	stderr := sExchangeDigEnvRsa(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}

		// case 0x6010:
		// 	stderr := sExchangeDigEnvRsa(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}
		// case 0x6011:
		// 	stderr := sExchangeDigEnvRsa(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}
		// case 0x6012:
		// 	stderr := sExchangeDigEnvEcc(conn, msgbody)
		// 	if stderr != nil {
		// 		slog.CServerLogWrite(slog.Error, connip,
		// 			"Crypto Server --> SDF_OpenSession Error Code[%08X]", stderr.Errcode)
		// 		b.PrintStdErr(stderr)
		// 	} else {
		// 		slog.CServerLogWrite(slog.Info, connip,
		// 			"Crypto Server --> SDF_OpenSession Success")
		// 	}

		case 0x6013:
			stderr := sGenKeyWithKek(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_GenerateKeyWithKEK Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_GenerateKeyWithKEK Success")
			}

		case 0x6014:
			stderr := sImportKeyWithKek(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ImportKeyWithKEK Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ImportKeyWithKEK Success")
			}

		case 0x6015:
			stderr := sImportKey(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ImportKey Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ImportKey Success")
			}

		case 0x6016:
			stderr := sDestoryKey(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_DestroyKey Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_DestroyKey Success")
			}

		case 0x7001:
			stderr := sExtPubKeyOpRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_OpenSession Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_OpenSession Success")
			}

		case 0x7002:
			stderr := sExtPrivKeyOpRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExternalPrivateKeyOperation_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExternalPrivateKeyOperation_RSA Success")
			}

		case 0x7003:
			stderr := sIntPubKeyOpRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_InternalPublicKeyOperation_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_InternalPublicKeyOperation_RSA Success")
			}

		case 0x7004:
			stderr := sIntPrivKeyOpRsa(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_InternalPrivateKeyOperation_RSA Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_InternalPrivateKeyOperation_RSA Success")
			}

		case 0x7005:
			stderr := sExtSigEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExternalSign_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExternalSign_ECC Success")
			}

		case 0x7006:
			stderr := sExtVifyEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExternalVerify_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExternalVerify_ECC Success")
			}

		case 0x7007:
			stderr := sIntSigEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_InternalSign_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_InternalSign_ECC Success")
			}

		case 0x7008:
			stderr := sIntVifyEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_InternalVerify_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_InternalVerify_ECC Success")
			}

		case 0x7009:
			stderr := sExtEncEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExternalEncrypt_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExternalEncrypt_ECC Success")
			}

		case 0x700A:
			stderr := sExtDecEcc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_ExternalDecrypt_ECC Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_ExternalDecrypt_ECC Success")
			}

		// case 0x7005:
		// 	stderr := sExtSigEcc(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}

		case 0x8001:
			stderr := sSymEnc(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_Encrypt Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_Encrypt Success")
			}

		case 0x8002:
			stderr := sSymDec(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_Decrypt Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_Decrypt Success")
			}

		// case 0x8003:
		// 	stderr := sSymMac(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}

		case 0x9001:
			stderr := sHashInit(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_HashInit Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_HashInit Success")
			}

		case 0x9002:
			stderr := sHashUpdate(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_HashUpdate Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_HashUpdate Success")
			}

		case 0x9003:
			stderr := sHashFinal(conn, msgbody)
			if stderr != nil {
				slog.CServerLogWrite(slog.Error, connip,
					"Crypto Server --> SDF_HashFinal Error Code[%08X]", stderr.Errcode)
				b.PrintStdErr(stderr)
			} else {
				slog.CServerLogWrite(slog.Info, connip,
					"Crypto Server --> SDF_HashFinal Success")
			}

		// case 0xA001:
		// 	stderr := sCreateFile(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}

		// case 0xA002:
		// 	stderr := sReadFile(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}

		// case 0xA003:
		// 	stderr := sWriteFile(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}

		// case 0xA004:
		// 	stderr := sDelFile(conn, msgbody)
		// 	if stderr != nil {
		// 		b.PrintStdErr(stderr)
		// 	}

		default:
			sendErrorMsgBack(conn, uint(b.UNKNOW_CMD))
		}
	}

}

// 设备管理类函数
// 1. 打开设备
// 0x5001
func sDevOpen(conn net.Conn) *b.StdErr {
	rtmsg := make([]byte, 8+8)
	binary.BigEndian.PutUint32(rtmsg, uint32(8))
	binary.BigEndian.PutUint32(rtmsg[4:], 0)
	conn.Write(rtmsg)
	return nil
}

// 2. 关闭设备
// 0x5002 msg : &devh[0-8]
func sDevClose(conn net.Conn) *b.StdErr {
	rtmsg := make([]byte, 8)
	binary.BigEndian.PutUint32(rtmsg, uint32(8))
	binary.BigEndian.PutUint32(rtmsg[4:], 0)
	conn.Write(rtmsg)
	return nil
}

// 3. 创建会话
// 0x5003
// rcv msg :
// snd msg : &sesh[0-8]
func sSesOpen(conn net.Conn) *b.StdErr {
	sesh, uiret := ISDF.OpenSession(CSDevH)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"OpenDevice Error ret : %08X", uiret)
	}

	rtmsg := make([]byte, 8+8)
	binary.BigEndian.PutUint32(rtmsg, 16)
	binary.BigEndian.PutUint32(rtmsg[4:], 0)
	binary.BigEndian.PutUint64(rtmsg[8:], uint64(uintptr(sesh)))
	conn.Write(rtmsg)
	return nil
}

// 4. 关闭会话
// 0x5004
// rcv msg : &sesh[0-8]
// snd msg :
func sSesClose(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	uiret := ISDF.CloseSession(sesh)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"CloseDevice Error ret : %08X", uiret)
	}

	rtmsg := make([]byte, 8)
	binary.BigEndian.PutUint32(rtmsg, uint32(8))
	binary.BigEndian.PutUint32(rtmsg[4:], 0)
	conn.Write(rtmsg)
	RWmu.Lock()
	SM2KeyCanUseList[conn] = nil
	RSAKeyCanUseList[conn] = nil
	CrySerStatus.ConnNums--
	RWmu.Unlock()
	return nil
}

// 5. 获取设备信息
// 0x5005
// rcv msg : &sesh[0-8]
// snd msg : devinfo_st[0-108]
func sGetDevInf(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	devinf, uiret := ISDF.GetDeviceInfo(
		sesh)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GetDeviceInfo Error ret : %08X", uiret)
	}
	len := 8 + 100
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], 0)
	*(*[40]byte)(rtmsg[8:]) = devinf.IssuerName
	*(*[16]byte)(rtmsg[48:]) = devinf.DeviceName
	*(*[16]byte)(rtmsg[64:]) = devinf.DeviceSerial
	binary.BigEndian.PutUint32(rtmsg[80:], uint32(devinf.DeviceVersion))
	binary.BigEndian.PutUint32(rtmsg[84:], uint32(devinf.StandardVersion))
	binary.BigEndian.PutUint32(rtmsg[88:], uint32(devinf.AsymAlgAbility[0]))
	binary.BigEndian.PutUint32(rtmsg[92:], uint32(devinf.AsymAlgAbility[1]))
	binary.BigEndian.PutUint32(rtmsg[96:], uint32(devinf.SymAlgAbility))
	binary.BigEndian.PutUint32(rtmsg[100:], uint32(devinf.HashAlgAbility))
	binary.BigEndian.PutUint32(rtmsg[104:], uint32(devinf.BufferSize))
	conn.Write(rtmsg)
	return nil
}

// 6. 产生随机数
// 0x5006
// rcv msg : &sesh[0-8] rlen[8-12]
// snd msg : rand[0-rlen]
func sGenRand(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	rlen := binary.BigEndian.Uint32(msg[8:])
	rand, uiret := ISDF.GenerateRandom(
		sesh, int(rlen))
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateRandom Error ret : %08X", uiret)
	} else {
		len := rlen + 8
		rtmsg := make([]byte, len)
		binary.BigEndian.PutUint32(rtmsg, uint32(len))
		binary.BigEndian.PutUint32(rtmsg[4:], 0)
		copy(rtmsg[8:], rand)
		conn.Write(rtmsg)
	}
	return nil
}

// 7. 获取私钥使用权限
// 0x5007
// rcv msg : &sesh[0-8] keyidx[8-12] psswd[12-]
// snd msg :
func sGetPrivKeyAccessRight(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	psswd := msg[12:]
	var ret int
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		sendErrorMsgBack(conn, uint(b.SDR_KEYNOTEXIST))
		return b.CreateStdErr(int(b.SDR_KEYNOTEXIST),
			"GetPrivateKeyAccessRight Error ret : %08X", b.SDR_KEYNOTEXIST)
	}
	if CSSm2Map[int(keyidx)].PrivKeyAuth == 0 {
		ret = 0
	} else {
		pwddig, uiret := ISDF.Hash(sesh, psswd)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"GetPrivateKeyAccessRight Error ret : %08X", uiret)
		}

		pivpin := CSSm2Map[int(keyidx)].PrivPin
		if bytes.Equal(pwddig, pivpin[:]) {
			ret = 0
			RWmu.Lock()
			SM2KeyCanUseList[conn][keyidx] = 1
			SM2KeyCanUseList[conn][keyidx+1] = 1
			RWmu.Unlock()

		} else {
			ret = b.SDR_PARDENY
			sendErrorMsgBack(conn, uint(ret))
			return b.CreateStdErr(int(ret),
				"GetPrivateKeyAccessRight Error ret : %08X", int(ret))
		}
	}

	len := 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(ret))
	conn.Write(rtmsg)
	return nil
}

// 8. 释放私钥使用权限
// 0x5008
// rcv msg : &sesh[0-8] keyidx[8-12]
// snd msg :
func sReleasePrivKeyAccessRight(conn net.Conn, msg []byte) *b.StdErr {
	// sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	RWmu.Lock()
	SM2KeyCanUseList[conn][keyidx] = 0
	SM2KeyCanUseList[conn][keyidx+1] = 0
	RWmu.Unlock()
	len := 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	conn.Write(rtmsg)
	return nil
}

// 密钥管理类函数
// 9. 导出RSA签名公钥
// 0x6001
// rcv msg : &sesh[0-8] keyidx[8-12]
// snd msg : rsasigpubkey[0-4+256+256]
func sExportRsaSigPubKey(conn net.Conn, msg []byte) *b.StdErr {
	// sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	var uiret uint
	if CSRsaMap[int(keyidx)] == nil || CSRsaMap[int(keyidx)].Idx != int(keyidx) {
		uiret = uint(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}

	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExportSigPublicKey_RSA Error ret : %08X", uiret)
	} else {
		len := 8 + 4 + 2*ISDF.LiteRSAref_MAX_LEN
		rtmsg := make([]byte, len)
		binary.BigEndian.PutUint32(rtmsg, uint32(len))
		binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
		binary.BigEndian.PutUint32(rtmsg[8:], uint32(CSRsaMap[int(keyidx)].PubKey.Bits))
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[12:]) = CSRsaMap[int(keyidx)].PubKey.M
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[12+ISDF.LiteRSAref_MAX_LEN:]) =
			CSRsaMap[int(keyidx)].PubKey.E
		conn.Write(rtmsg)
	}
	return nil
}

// 10. 导出RSA加密公钥
// 0x6002
// rcv msg : &sesh[0-8] keyidx[8-12]
// snd msg : rsaencpubkey[0-4+256+256]
func sExportRsaEncPubKey(conn net.Conn, msg []byte) *b.StdErr {
	// sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	var uiret uint
	if CSRsaMap[int(keyidx)] == nil || CSRsaMap[int(keyidx)].Idx != int(keyidx) {
		uiret = uint(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}

	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExportSigPublicKey_RSA Error ret : %08X", uiret)
	} else {
		len := 8 + 4 + 2*ISDF.LiteRSAref_MAX_LEN
		rtmsg := make([]byte, len)
		binary.BigEndian.PutUint32(rtmsg, uint32(len))
		binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
		binary.BigEndian.PutUint32(rtmsg[8:], uint32(CSRsaMap[int(keyidx)].PubKey.Bits))
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[12:]) = CSRsaMap[int(keyidx)].PubKey.M
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[12+ISDF.LiteRSAref_MAX_LEN:]) =
			CSRsaMap[int(keyidx)].PubKey.E
		conn.Write(rtmsg)
	}
	return nil
}

// 11. 产生RSA非对称密钥对并输出
// 0x6003
// rcv msg : &sesh[0-8] keybits[8-12]
// snd msg : rsapubkey[0-516] rsapivkey[516-]
func sGenRsaKeyPair(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyBits := binary.BigEndian.Uint32(msg[8:])

	pubk, pivk, uiret := ISDF.GenerateKeyPairRSA(sesh, int(keyBits))
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyPair_RSA Error ret : %08X", uiret)
	} else {
		len := 8 + 4 + ISDF.LiteRSAref_MAX_LEN*2 +
			4 + ISDF.LiteRSAref_MAX_LEN*5 + ISDF.LiteRSAref_MAX_LEN/2
		rtmsg := make([]byte, len)
		binary.BigEndian.PutUint32(rtmsg, uint32(len))
		binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
		binary.BigEndian.PutUint32(rtmsg[8:], uint32(pubk.Bits))
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[12:]) = pubk.M
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[12+ISDF.LiteRSAref_MAX_LEN:]) = pubk.E
		binary.BigEndian.PutUint32(rtmsg[12+ISDF.LiteRSAref_MAX_LEN*2:], uint32(pivk.Bits))
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*2:]) = pivk.M
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*3:]) = pivk.E
		*(*[ISDF.LiteRSAref_MAX_LEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*4:]) = pivk.D
		*(*[ISDF.LiteRSAref_MAX_PLEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*5:]) = pivk.Prime[0]
		*(*[ISDF.LiteRSAref_MAX_PLEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*5+ISDF.LiteRSAref_MAX_LEN/2:]) = pivk.Prime[1]
		*(*[ISDF.LiteRSAref_MAX_PLEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*6:]) = pivk.Pexp[0]
		*(*[ISDF.LiteRSAref_MAX_PLEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*6+ISDF.LiteRSAref_MAX_LEN/2:]) = pivk.Pexp[1]
		*(*[ISDF.LiteRSAref_MAX_PLEN]byte)(rtmsg[16+ISDF.LiteRSAref_MAX_LEN*7:]) = pivk.Coef
		conn.Write(rtmsg)
	}
	return nil
}

// 12. 生成会话密钥并用内部RSA公钥加密输出
// 0x6004
// rcv msg : &sesh[0-8] keyidx[8-12] keybits[12-16]
// snd msg : key[0-keybits/8] keyh[keybits/8-keybits/8+8]
func sGenKeyWithIPKRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	keybits := binary.BigEndian.Uint32(msg[12:])

	var uiret int
	if CSRsaMap[int(keyidx)] == nil || CSRsaMap[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}
	rpk := CSRsaMap[int(keyidx)].PubKey

	r, uiret := ISDF.GenerateRandom(sesh, int(keybits/8))
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	var zarry = make([]byte, rpk.Bits/8)
	copy(zarry[len(zarry)-int(keybits/8):], r)
	zarry[0] = byte(keybits / 8)
	key, uiret := ISDF.ExternalPublicKeyOperationRSA(sesh, &rpk, zarry)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	keyh, uiret := ISDF.ImportKey(sesh, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	keylen := len(key)
	len := 8 + 8 + keylen
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], key)
	binary.BigEndian.PutUint64(rtmsg[8+keylen:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil

}

// 13. 生成会话密钥并用外部RSA公钥加密输出
// 0x6005
// rcv msg : &sesh[0-8] keybits[8-12] rsakey[12-]
// snd msg : key[0-keybits/8] keyh[keybits/8-keybits/8+8]
func sGenKeyWithEPKRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keybits := binary.BigEndian.Uint32(msg[8:])
	rpk := GetRSAPubKeyFromMsg(msg[12:])

	r, uiret := ISDF.GenerateRandom(sesh, int(keybits/8))
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	var zarry = make([]byte, rpk.Bits/8)
	copy(zarry[len(zarry)-int(keybits/8):], r)
	zarry[0] = byte(keybits / 8)

	key, uiret := ISDF.ExternalPublicKeyOperationRSA(sesh, rpk, zarry)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
	}
	keyh, uiret := ISDF.ImportKey(sesh, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	keylen := len(key)
	len := 8 + 8 + keylen
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], key)
	binary.BigEndian.PutUint64(rtmsg[8+keylen:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil

}

// 14. 导入会话密钥并用内部RSA私钥解密
// 0x6006
// rcv msg : &sesh[0-8] keyidx[8-12] ekey[12-12+keylen]
// snd msg : keyh[0-8]
func sImpKeyWithISKRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])

	var uiret int
	if CSRsaMap[int(keyidx)] == nil || CSRsaMap[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}

	if RSAKeyCanUseList[conn][keyidx] == 0 && CSRsaMap[int(keyidx)].PrivKeyAuth != 0 {
		uiret = int(b.SDR_PARDENY)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}

	rpivk := CSRsaMap[int(keyidx)].PrivKey
	key, uiret := ISDF.ExternalPrivateKeyOperationRSA(sesh, &rpivk, msg[12:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	keylen := key[0]
	offset := len(key) - int(keylen)
	keyh, uiret := ISDF.ImportKey(sesh, key[offset:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	len := 8 + 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	binary.BigEndian.PutUint64(rtmsg[8:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil
}

// 15. 基于RSA算法的数字信封转换
// 0x6007
// rcv msg : &sesh[0-8] keyidx[8-12] rsapubk[12-12+4+ISDF.LiteRSAref_MAX_LEN*2] encedmsg[12+4+ISDF.LiteRSAref_MAX_LEN*2-]
// snd msg : reencedmsg[0-]
func sExchangeDigEnvRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	rpk := GetRSAPubKeyFromMsg(msg[12:])

	var uiret int
	if CSRsaMap[int(keyidx)] == nil || CSRsaMap[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}
	if RSAKeyCanUseList[conn][keyidx] == 0 && CSRsaMap[int(keyidx)].PrivKeyAuth != 0 {
		uiret = int(b.SDR_PARDENY)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}

	rpivk := CSRsaMap[int(keyidx)].PrivKey
	key, uiret := ISDF.ExternalPrivateKeyOperationRSA(sesh, &rpivk, msg[12+4+ISDF.LiteRSAref_MAX_LEN*2:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	reekey, uiret := ISDF.ExternalPublicKeyOperationRSA(sesh, rpk, key)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_RSA Error ret : %08X", uiret)
	}

	keylen := len(reekey)
	len := 8 + 8 + keylen
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], reekey)
	conn.Write(rtmsg)
	return nil
}

// 16. 导出ECC签名公钥
// 0x6008
// rcv msg : &sesh[0-8] keyidx[8-12]
// snd msg : sigkey[0-]
func sExportEccSigKey(conn net.Conn, msg []byte) *b.StdErr {
	// sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	var uiret uint
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		uiret = uint(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}

	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExportSigPublicKey_ECC Error ret : %08X", uiret)
	} else {
		len := 8 + 4 + 2*ISDF.ECCref_MAX_LEN
		rtmsg := make([]byte, len)
		binary.BigEndian.PutUint32(rtmsg, uint32(len))
		binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
		binary.BigEndian.PutUint32(rtmsg[8:], uint32(CSSm2Map[int(keyidx)].PubKey.Bits))
		*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[12:]) = CSSm2Map[int(keyidx)].PubKey.X
		*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[12+ISDF.ECCref_MAX_LEN:]) =
			CSSm2Map[int(keyidx)].PubKey.Y
		conn.Write(rtmsg)
	}
	return nil
}

// 17. 导出ECC加密公钥
// 0x6009
// rcv msg : &sesh[0-8] keyidx[8-12]
// snd msg : enckey[0-]
func sExportEccEncKey(conn net.Conn, msg []byte) *b.StdErr {
	// sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	var uiret uint
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		uiret = uint(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}

	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExportSigPublicKey_ECC Error ret : %08X", uiret)
	} else {
		len := 8 + 4 + 2*ISDF.ECCref_MAX_LEN
		rtmsg := make([]byte, len)
		binary.BigEndian.PutUint32(rtmsg, uint32(len))
		binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
		binary.BigEndian.PutUint32(rtmsg[8:], uint32(CSSm2Map[int(keyidx)].PubKey.Bits))
		*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[12:]) = CSSm2Map[int(keyidx)].PubKey.X
		*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[12+ISDF.ECCref_MAX_LEN:]) =
			CSSm2Map[int(keyidx)].PubKey.Y
		conn.Write(rtmsg)
	}
	return nil
}

// 18. 产生ECC非对称密钥对并输出
// 0x600A
// rcv msg : &sesh[0-8] keybits[8-12]
// snd msg : pubkey[0-132] privkey[132-]
func sGenEccKeyPair(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keybits := binary.BigEndian.Uint32(msg[8:])

	ecpubk, ecpivk, uiret := ISDF.GenerateKeyPairECC(sesh, ISDF.SGD_SM2, int(keybits))
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyPair_ECC Error ret : %08X", uiret)
	}
	len := 8 + 4 + ISDF.ECCref_MAX_LEN*2 + 4 + ISDF.ECCref_MAX_LEN
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	binary.BigEndian.PutUint32(rtmsg[8:], uint32(ecpubk.Bits))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[12:]) = ecpubk.X
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[12+ISDF.ECCref_MAX_LEN:]) = ecpubk.Y
	binary.BigEndian.PutUint32(rtmsg[12+ISDF.ECCref_MAX_LEN*2:], uint32(ecpivk.Bits))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[16+ISDF.ECCref_MAX_LEN*2:]) = ecpivk.K
	conn.Write(rtmsg)

	return nil
}

// 19. 生成会话密钥并用内部ECC公钥加密输出
// 0x600B
// rcv msg : &sesh[0-8] keyidx[8-12] keybits[12-16]
// snd msg : ecccip[0-300] keyh[300-308]
func sGenKeyWithIPKEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	keybits := binary.BigEndian.Uint32(msg[12:])

	var uiret int
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}
	epk := CSSm2Map[int(keyidx)].PubKey

	r, uiret := ISDF.GenerateRandom(sesh, int(keybits/8))
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_ECC Error ret : %08X", uiret)
	}

	ecccip, uiret := ISDF.ExternalEncryptECC(sesh, ISDF.SGD_SM2_3, &epk, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_ECC Error ret : %08X", uiret)
	}
	keyh, uiret := ISDF.ImportKey(sesh, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_ECC Error ret : %08X", uiret)
	}

	len := 8 + ISDF.ECCref_MAX_LEN*2 + ISDF.ECCref_MAX_LEN/2 + 4 + ISDF.ECCref_CIPHER_LEN + 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8:]) = ecccip.X
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN:]) = ecccip.Y
	*(*[ISDF.ECCref_MAX_LEN / 2]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN*2:]) = ecccip.M
	binary.BigEndian.PutUint32(rtmsg[8+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:], uint32(ecccip.L))
	*(*[ISDF.ECCref_CIPHER_LEN]byte)(rtmsg[12+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:]) = ecccip.C
	binary.BigEndian.PutUint64(rtmsg[12+ISDF.ECCref_MAX_LEN*2+
		ISDF.ECCref_MAX_LEN/2+ISDF.ECCref_CIPHER_LEN:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil
}

// 20. 生成会话密钥并用外部ECC公钥加密输出
// 0x600C
// rcv msg : &sesh[0-8] keybits[8-12] eccpubk[12-]
// snd msg : ecccip[0-300] keyh[300-308]
func sGenKeyWithEPKEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keybits := binary.BigEndian.Uint32(msg[8:])
	epk := GetECCPubKeyFromMsg(msg[12:])

	r, uiret := ISDF.GenerateRandom(sesh, int(keybits/8))
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_ECC Error ret : %08X", uiret)
	}

	ecccip, uiret := ISDF.ExternalEncryptECC(sesh, ISDF.SGD_SM2_3, epk, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_ECC Error ret : %08X", uiret)
	}
	keyh, uiret := ISDF.ImportKey(sesh, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithIPK_ECC Error ret : %08X", uiret)
	}

	len := 8 + ISDF.ECCref_MAX_LEN*2 + ISDF.ECCref_MAX_LEN/2 + 4 + ISDF.ECCref_CIPHER_LEN + 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8:]) = ecccip.X
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN:]) = ecccip.Y
	*(*[ISDF.ECCref_MAX_LEN / 2]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN*2:]) = ecccip.M
	binary.BigEndian.PutUint32(rtmsg[8+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:], uint32(ecccip.L))
	*(*[ISDF.ECCref_CIPHER_LEN]byte)(rtmsg[12+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:]) = ecccip.C
	binary.BigEndian.PutUint64(rtmsg[12+ISDF.ECCref_MAX_LEN*2+
		ISDF.ECCref_MAX_LEN/2+ISDF.ECCref_CIPHER_LEN:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil
}

// 21. 导入会话密钥并用内部ECC私钥解密
// 0x600D
// rcv msg : &sesh[0-8] keyidx[8-12] ecccip[12-]
// snd msg : keyh[0-8]
func sImpKeyWithISKEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	ecccip := (*ISDF.ECCCipher)(unsafe.Pointer(&msg[12]))
	ecccip.L = uint(binary.BigEndian.Uint32(msg[12+160 : 176]))
	ecccip.C = *(*[ISDF.ECCref_CIPHER_LEN]byte)(unsafe.Pointer(&msg[180]))

	var uiret int
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}
	if SM2KeyCanUseList[conn][keyidx] == 0 && CSSm2Map[int(keyidx)].PrivKeyAuth != 0 {
		uiret = int(b.SDR_PARDENY)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithISK_ECC Error ret : %08X", uiret)
		}
	}

	spivk := CSSm2Map[int(keyidx)].PrivKey
	key, uiret := ISDF.ExternalDecryptECC(sesh, ISDF.SGD_SM2, &spivk, ecccip)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKeyWithISK_ECC Error ret : %08X", uiret)
	}

	keyh, uiret := ISDF.ImportKey(sesh, key)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKeyWithISK_ECC Error ret : %08X", uiret)
	}

	len := 8 + 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	binary.BigEndian.PutUint64(rtmsg[8:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil
}

// // 22. 生成密钥协商参数并输出
// // 0x600E
// // rcv msg : &sesh[0-8] keyidx[8-12] keybits[12-16] sponsorid[16-]
// // snd msg : sppubk[0-132] sptmppubk[132-264] agreeh[264-]
// func sGenAgreementEcc(conn net.Conn, msg []byte) *b.StdErr {
// 	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
// 	keyidx := binary.BigEndian.Uint32(msg[8:])
// 	keybits := binary.BigEndian.Uint32(msg[12:])

// 	var uiret uint
// 	if CSSm2Map[int(keyidx)].KeyType == 0 || CSSm2Map[int(keyidx)].KeyType == 1 {
// 		uiret = uint(b.SDR_KEYNOTEXIST)
// 		if uiret != 0 {
// 			sendErrorMsgBack(conn, uint(uiret))
// 			return b.CreateStdErr(int(uiret),
// 				"GenerateAgreementDataWithECC Error ret : %08X", uiret)
// 		}
// 	}
// 	if SM2KeyCanUseList[conn][keyidx] == 0 && CSSm2Map[int(keyidx)].PrivKeyAuth != 0 {
// 		uiret = uint(b.SDR_PARDENY)
// 		if uiret != 0 {
// 			sendErrorMsgBack(conn, uint(uiret))
// 			return b.CreateStdErr(int(uiret),
// 				"GenerateAgreementDataWithECC Error ret : %08X", uiret)
// 		}
// 	}

// 	return nil
// }

// 25. 基于 ECC算法的数字信封转换
// 0x6012
// rcv msg : &sesh[0-8] keyidx[8-12] ecpubk[12-144] eccip[144-344(348)]
// snd msg : eccip[0-]
func sExchangeDigEnvEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])
	ecpubk := GetECCPubKeyFromMsg(msg[12:])
	ecccip := GetECCCipherFromMsg(msg[144:])

	var uiret int
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}

	if SM2KeyCanUseList[conn][keyidx] == 0 && CSSm2Map[int(keyidx)].PrivKeyAuth != 0 {
		uiret = int(b.SDR_PARDENY)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ExchangeDigitEnvelopeBaseOnECC Error ret : %08X", uiret)
		}
	}

	epivk := CSSm2Map[int(keyidx)].PrivKey
	mdata, uiret := ISDF.ExternalDecryptECC(sesh, ISDF.SGD_SM2, &epivk, ecccip)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExchangeDigitEnvelopeBaseOnECC Error ret : %08X", uiret)
	}

	neccip, uiret := ISDF.ExternalEncryptECC(sesh, ISDF.SGD_SM2, ecpubk, mdata)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExchangeDigitEnvelopeBaseOnECC Error ret : %08X", uiret)
	}
	len := 8 + ISDF.ECCref_MAX_LEN*2 + ISDF.ECCref_MAX_LEN/2 + 4 + ISDF.ECCref_CIPHER_LEN
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8:]) = neccip.X
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN:]) = neccip.Y
	*(*[ISDF.ECCref_MAX_LEN / 2]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN*2:]) = neccip.M
	binary.BigEndian.PutUint32(rtmsg[8+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:], uint32(neccip.L))
	*(*[ISDF.ECCref_CIPHER_LEN]byte)(rtmsg[12+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:]) = neccip.C
	conn.Write(rtmsg)
	return nil
}

// 26. 生成会话密钥并用密钥加密密钥加密输出
// 0x6013
// rcv msg : &sesh[0-8] keybits[8-12] algid[12-16] keyidx[16-20]
// snd msg : enckey[0-keylen] keyh[keylen-]
func sGenKeyWithKek(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keybits := binary.BigEndian.Uint32(msg[8:])
	algid := binary.BigEndian.Uint32(msg[12:])
	keyidx := binary.BigEndian.Uint32(msg[16:])

	var uiret int
	if CSSymMap[int(keyidx)] == nil || CSSymMap[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"GenerateKeyWithKEK Error ret : %08X", uiret)
		}
	}

	r, uiret := ISDF.GenerateRandom(sesh, int(keybits)/8)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithKEK Error ret : %08X", uiret)
	}

	enckey, uiret := ISDF.EncryptEx(sesh,
		CSSymMap[int(keyidx)].KeyValue, int(algid), nil, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithKEK Error ret : %08X", uiret)
	}

	keyh, uiret := ISDF.ImportKey(sesh, r)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithKEK Error ret : %08X", uiret)
	}

	enckeylen := len(enckey)
	len := 8 + 8 + enckeylen
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], enckey)
	binary.BigEndian.PutUint64(rtmsg[uint(8+enckeylen):], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil
}

// 27. 导入会话密钥并用密钥加密密钥解密
// 0x6014
// rcv msg : &sesh[0-8] algid[8-12] keyidx[12-16] enck[16-]
// snd msg : keyh[0-8]
func sImportKeyWithKek(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	algid := binary.BigEndian.Uint32(msg[8:])
	keyidx := binary.BigEndian.Uint32(msg[12:])

	var uiret int
	if CSSymMap[int(keyidx)].Idx == 0 {
		uiret = int(b.SDR_KEYNOTEXIST)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithKEK Error ret : %08X", uiret)
		}
	}

	deckey, uiret := ISDF.DecryptEx(sesh,
		CSSymMap[int(keyidx)].KeyValue, int(algid), nil, msg[16:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"GenerateKeyWithKEK Error ret : %08X", uiret)
	}

	keyh, uiret := ISDF.ImportKey(sesh, deckey)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKey Error ret : %08X", uiret)
	}

	len := 8 + 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	binary.BigEndian.PutUint64(rtmsg[8:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil
}

// 28. 导入明文会话密钥
// 0x6015
// rcv msg : &sesh[0-8] key[8-]
// snd msg : keyh[0-8]
func sImportKey(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyh, uiret := ISDF.ImportKey(sesh, msg[8:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKey Error ret : %08X", uiret)
	}
	len := 8 + 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	binary.BigEndian.PutUint64(rtmsg[8:], uint64(uintptr(keyh)))
	conn.Write(rtmsg)
	return nil
}

// 29. 销毁会话密钥
// 0x6016
// rcv msg : &sesh[0-8] keyh[8-16]
// snd msg :
func sDestoryKey(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[8:16])))

	uiret := ISDF.DestroyKey(sesh, keyh)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ImportKey Error ret : %08X", uiret)
	}

	len := 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	conn.Write(rtmsg)
	return nil
}

// 非对称算法运算类函数
// 30. 外部公钥RSA运算
// 0x7001
// rcv msg : &sesh[0-8] rsapk[8-1036] indata[1036-]
// snd msg : outdata[0-]
func sExtPubKeyOpRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	rpk := GetRSAPubKeyFromMsg(msg[8:])

	// fmt.Println("rpk = ", rpk)
	outdata, uiret := ISDF.ExternalPublicKeyOperationRSA(sesh, rpk, msg[8+4+ISDF.LiteRSAref_MAX_LEN*2:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExternalPublicKeyOperation_RSA Error ret : %08X", uiret)
	}

	len := 8 + len(outdata)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], outdata)
	conn.Write(rtmsg)
	return nil
}

// 31. 外部私钥RSA运算
// 0x7002
// rcv msg : &sesh[0-8] rsapivk[8-2828] indata[2828-]
// snd msg : outdata[0-]
func sExtPrivKeyOpRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	rpivk := GetRSAPivKeyFromMsg(msg[8:])

	outdata, uiret := ISDF.ExternalPrivateKeyOperationRSA(sesh, rpivk, msg[8+4+ISDF.LiteRSAref_MAX_PLEN*11:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExternalPrivateKeyOperation_RSA Error ret : %08X", uiret)
	}
	len := 8 + len(outdata)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], outdata)
	conn.Write(rtmsg)
	return nil
}

// 32. 内部公钥RSA运算
// 0x7003
// rcv msg : &sesh[0-8] keyidx[8-12] indata[12-]
// snd msg : outdata[0-]
func sIntPubKeyOpRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])

	var uiret int
	if CSRsaMap[int(keyidx)] == nil || CSRsaMap[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}
	rsaPk := CSRsaMap[int(keyidx)].PubKey
	outdata, uiret := ISDF.ExternalPublicKeyOperationRSA(sesh, &rsaPk, msg[12:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"InternalPublicKeyOperation_RSA Error ret : %08X", uiret)
	}

	len := 8 + len(outdata)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], outdata)
	conn.Write(rtmsg)
	return nil
}

// 33. 内部私RSA运算
// 0x7004
// rcv msg : &sesh[0-8] keyidx[8-12] indata[12-]
// snd msg : outdata[0-]
func sIntPrivKeyOpRsa(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := binary.BigEndian.Uint32(msg[8:])

	var uiret int
	if CSRsaMap[int(keyidx)] == nil || CSRsaMap[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}
	if RSAKeyCanUseList[conn][keyidx] == 0 && CSRsaMap[int(keyidx)].PrivKeyAuth != 0 {
		uiret = int(b.SDR_PARDENY)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"ImportKeyWithIPK_RSA Error ret : %08X", uiret)
		}
	}

	rpivk := CSRsaMap[int(keyidx)].PrivKey
	// fmt.Println("rpk = ", rpk)
	outdata, uiret := ISDF.ExternalPrivateKeyOperationRSA(sesh, &rpivk, msg[12:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"InternalPrivateKeyOperation_RSA Error ret : %08X", uiret)
	}

	len := 8 + len(outdata)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	copy(rtmsg[8:], outdata)
	conn.Write(rtmsg)
	return nil
}

// 34. 外部密钥ECC签名
// 0x7005
// rcv msg : &sesh[0-8] ecpivk[8-76] indata[76-108]
// snd msg : ecsig[0-128]
func sExtSigEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	epivk := GetECCPivKeyFromMsg(msg[8:])

	var uiret int
	ecsig, uiret := ISDF.ExternalSignECC(sesh, ISDF.SGD_SM2_1, epivk, msg[8+4+ISDF.ECCref_MAX_LEN:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExternalSign_ECC Error ret : %08X", uiret)
	}

	len := 8 + ISDF.ECCref_MAX_LEN*2
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8:]) = ecsig.R
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN:]) = ecsig.S
	conn.Write(rtmsg)
	return nil
}

// 35. 外部密钥ECC验证
// 0x7006
// rcv msg : &sesh[0-8] ecpubk[8-140] ecsig[140-268] indata[268-300]
// snd msg :
func sExtVifyEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	epk := GetECCPubKeyFromMsg(msg[8:])
	esig := GetECCSigFromMsg(msg[140:])

	uiret := ISDF.ExternalVerifyECC(sesh, ISDF.SGD_SM2_1, epk, msg[8+4+ISDF.ECCref_MAX_LEN*4:], esig)

	len := 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	conn.Write(rtmsg)
	return nil
}

// 36. 内部密钥ECC签名
// 0x7007
// rcv msg : &sesh[0-8] keyidx[8-12] indata[12-12+32]
// snd msg : ecsig[0-128]
func sIntSigEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := uint(binary.BigEndian.Uint32(msg[8:]))

	var uiret int
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}

	if SM2KeyCanUseList[conn][keyidx] == 0 && CSSm2Map[int(keyidx)].PrivKeyAuth != 0 {
		uiret = int(b.SDR_PARDENY)
		if uiret != 0 {
			sendErrorMsgBack(conn, uint(uiret))
			return b.CreateStdErr(int(uiret),
				"InternalSign_ECC Error ret : %08X", uiret)
		}
	}

	epivk := CSSm2Map[int(keyidx)].PrivKey

	ecsig, uiret := ISDF.ExternalSignECC(sesh, ISDF.SGD_SM2_1, &epivk, msg[12:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"InternalSign_ECC Error ret : %08X", uiret)
	}

	len := 8 + ISDF.ECCref_MAX_LEN*2
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(0))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8:]) = ecsig.R
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN:]) = ecsig.S
	conn.Write(rtmsg)
	return nil
}

// 37. 内部密钥ECC验证
// 0x7008
// rcv msg : &sesh[0-8] keyidx[8-12] ecsig[12-140] indata[140-]
// snd msg :
func sIntVifyEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyidx := uint(binary.BigEndian.Uint32(msg[8:]))
	esig := GetECCSigFromMsg(msg[12:])

	var uiret int
	if CSSm2Map[int(keyidx)] == nil || CSSm2Map[int(keyidx)].Idx != int(keyidx) {
		uiret = int(b.SDR_KEYNOTEXIST)
	} else {
		uiret = 0
	}

	epk := CSSm2Map[int(keyidx)].PubKey
	uiret = ISDF.ExternalVerifyECC(sesh, ISDF.SGD_SM2_1, &epk, msg[12+ISDF.ECCref_MAX_LEN*2:], esig)

	len := 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	conn.Write(rtmsg)
	return nil
}

// 38. 外部密钥ECC加密
// 0x7009
// rcv msg : &sesh[0-8] ecpubk[8-140] indata[140-]
// snd msg : ecccip[0-300]
func sExtEncEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	epk := GetECCPubKeyFromMsg(msg[8:])

	ecccip, uiret := ISDF.ExternalEncryptECC(sesh, ISDF.SGD_SM2_3, epk, msg[8+4+ISDF.ECCref_MAX_LEN*2:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExternalEncrypt_ECC Error ret : %08X", uiret)
	}
	len := 8 + ISDF.ECCref_MAX_LEN*2 + ISDF.ECCref_MAX_LEN/2 + 4 + ISDF.ECCref_CIPHER_LEN
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8:]) = ecccip.X
	*(*[ISDF.ECCref_MAX_LEN]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN:]) = ecccip.Y
	*(*[ISDF.ECCref_MAX_LEN / 2]byte)(rtmsg[8+ISDF.ECCref_MAX_LEN*2:]) = ecccip.M
	binary.BigEndian.PutUint32(rtmsg[8+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:], uint32(ecccip.L))
	*(*[ISDF.ECCref_CIPHER_LEN]byte)(rtmsg[12+ISDF.ECCref_MAX_LEN*2+ISDF.ECCref_MAX_LEN/2:]) = ecccip.C

	conn.Write(rtmsg)
	return nil
}

// 39. 外部密钥ECC解密
// 0x700A
// rcv msg : &sesh[0-8] ecpivk[8-76] ecccip[76-376]
// snd msg : dedata[0-]
func sExtDecEcc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	epivk := GetECCPivKeyFromMsg(msg[8:])
	ecccip := GetECCCipherFromMsg(msg[8+4+ISDF.ECCref_MAX_LEN:])
	dedata, uiret := ISDF.ExternalDecryptECC(sesh, ISDF.SGD_SM2, epivk, ecccip)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"ExternalDecrypt_ECC Error ret : %08X", uiret)
	}

	len := 8 + len(dedata)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	copy(rtmsg[8:], dedata)
	conn.Write(rtmsg)
	return nil
}

// 40. 对称加密
// 0x8001
// rcv msg : &sesh[0-8] keyh[8-16] algid[16-20] iv[20-36] data[36-]
// snd msg : encdata[0-]
func sSymEnc(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[8:16])))
	algid := binary.BigEndian.Uint32(msg[16:])
	iv := msg[20:36]

	encdata, uiret := ISDF.Encrypt(sesh, keyh, int(algid), iv, msg[36:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"Encrypt Error ret : %08X", uiret)
	}

	len := 8 + len(encdata)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	copy(rtmsg[8:], encdata)
	conn.Write(rtmsg)
	return nil
}

// 41. 对称解密
// 0x8002
// rcv msg : &sesh[0-8] keyh[8-16] algid[16-20] iv[20-36] encdata[36-]
// snd msg : data[0-]
func sSymDec(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	keyh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[8:16])))
	algid := binary.BigEndian.Uint32(msg[16:])
	iv := msg[20:36]

	decdata, uiret := ISDF.Decrypt(sesh, keyh, int(algid), iv, msg[36:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"Decrypt Error ret : %08X", uiret)
	}

	len := 8 + len(decdata)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	copy(rtmsg[8:], decdata)
	conn.Write(rtmsg)
	return nil
}

// // 42. 计算ＭＡＣ
// // 0x8002
// // rcv msg : &sesh[0-8] keyh[8-16] algid[16-20] iv[20-36] data[36-]
// // snd msg : mac[0-]
// func sSymMac(conn net.Conn, msg []byte) *b.StdErr {
// 	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
// 	keyh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[8:16])))
// 	algid := binary.BigEndian.Uint32(msg[16:])
// 	iv := msg[20:36]

// 	decdata, uiret := ISDF.CalculateMAC(sesh, keyh, uint(algid), iv, msg[36:])
// 	if uiret != 0 {
// 		sendErrorMsgBack(conn, uint(uiret))
// 		return b.CreateStdErr(int(uiret),
// 			"CalculateMAC Error ret : %08X", uiret)
// 	}

// 	len := 8 + len(decdata)
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
// 	copy(rtmsg[8:], decdata)
// 	conn.Write(rtmsg)
// 	return nil
// }

// 杂凑运算类函数
// 43. 杂凑运算初始化
// 0x9001
// rcv msg : &sesh[0-8] ecpubk[8-140] pucid[140-]
// snd msg :
func sHashInit(conn net.Conn, msg []byte) *b.StdErr {
	var pucid []byte
	var ecpubk *ISDF.ECCrefPublicKey
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	if len(msg) > int(8+ISDF.ECCref_MAX_LEN*2+4) {
		ecpubk = GetECCPubKeyFromMsg(msg[8:])
		pucid = msg[8+ISDF.ECCref_MAX_LEN*2+4:]
	} else {
		pucid = nil
		ecpubk = nil
	}

	uiret := ISDF.HashInit(sesh, ISDF.SGD_SM3, ecpubk, pucid)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"HashInit Error ret : %08X", uiret)
	}

	len := 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	conn.Write(rtmsg)
	return nil
}

// 44. 多包杂凑运算
// 0x9002
// rcv msg : &sesh[0-8] data[8-]
// snd msg :
func sHashUpdate(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
	uiret := ISDF.HashUpdate(sesh, msg[8:])
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"HashInit Error ret : %08X", uiret)
	}

	len := 8
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	conn.Write(rtmsg)
	return nil
}

// 45. 杂凑运算结束
// 0x9003
// rcv msg : &sesh[0-8]
// snd msg : digest[0-32]
func sHashFinal(conn net.Conn, msg []byte) *b.StdErr {
	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))

	digest, uiret := ISDF.HashFinal(sesh)
	if uiret != 0 {
		sendErrorMsgBack(conn, uint(uiret))
		return b.CreateStdErr(int(uiret),
			"HashInit Error ret : %08X", uiret)
	}

	len := 8 + len(digest)
	rtmsg := make([]byte, len)
	binary.BigEndian.PutUint32(rtmsg, uint32(len))
	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
	copy(rtmsg[8:], digest)
	conn.Write(rtmsg)
	return nil
}

// // 用户文件操作类函数
// // 46. 创建文件
// // 0xA001
// // rcv msg : &sesh[0-8] filesize[8-12] filename[12-]
// // snd msg :
// func sCreateFile(conn net.Conn, msg []byte) *b.StdErr {
// 	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
// 	filesize := binary.BigEndian.Uint32(msg[8:])

// 	uiret := ISDF.CreateFile(sesh, msg[12:], uint(filesize))

// 	len := 8
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
// 	conn.Write(rtmsg)
// 	return nil
// }

// // 47. 读取文件
// // 0xA002
// // rcv msg : &sesh[0-8] fileoffset[8-12] readlen[12-16] filename[16-]
// // snd msg : data[0-]
// func sReadFile(conn net.Conn, msg []byte) *b.StdErr {
// 	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
// 	fileoffset := binary.BigEndian.Uint32(msg[8:])
// 	readlen := binary.BigEndian.Uint32(msg[12:])

// 	readv, uiret := ISDF.ReadFile(sesh, msg[16:], uint(fileoffset), uint(readlen))
// 	if uiret != 0 {
// 		sendErrorMsgBack(conn, uint(uiret))
// 		return b.CreateStdErr(int(uiret),
// 			"HashInit Error ret : %08X", uiret)
// 	}

// 	len := 8 + len(readv)
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
// 	copy(rtmsg[8:], readv)
// 	conn.Write(rtmsg)
// 	return nil
// }

// // 48. 写文件
// // 0xA003
// // rcv msg : &sesh[0-8] fileoffset[8-12] namelen[12-16] filename[16-16+namelen] write[16+namelen-]
// // snd msg :
// func sWriteFile(conn net.Conn, msg []byte) *b.StdErr {
// 	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))
// 	fileoffset := binary.BigEndian.Uint32(msg[8:])
// 	namelen := binary.BigEndian.Uint32(msg[12:])

// 	uiret := ISDF.WriteFile(sesh, msg[16:16+namelen], uint(fileoffset), msg[16+namelen:])

// 	len := 8
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
// 	conn.Write(rtmsg)
// 	return nil
// }

// // 48. 写文件
// // 49. 删除文件
// // rcv msg : &sesh[0-8] filename[8-]
// // snd msg :
// func sDelFile(conn net.Conn, msg []byte) *b.StdErr {
// 	sesh := unsafe.Pointer(uintptr(binary.BigEndian.Uint64(msg[:8])))

// 	uiret := ISDF.DeleteFile(sesh, msg[8:])
// 	len := 8
// 	rtmsg := make([]byte, len)
// 	binary.BigEndian.PutUint32(rtmsg, uint32(len))
// 	binary.BigEndian.PutUint32(rtmsg[4:], uint32(uiret))
// 	conn.Write(rtmsg)
// 	return nil
// }
