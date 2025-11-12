package ISDF

/*
#cgo CFLAGS: -I ./inc/
#cgo LDFLAGS: -L ./lib  -Wl,-rpath=./lib -lsoftsdf
#include "sdf.h"
*/
import "C"
import (
	"unsafe"
	// "github.com/emmansun/gmsm/ecdsa"
)

func ConvertToDevinfoGO(cdevinfo *C.DEVICEINFO) *DeviceInof {
	if cdevinfo == nil {
		return nil
	}

	var godevinfo DeviceInof
	godevinfo.IssuerName = *(*[40]byte)(unsafe.Pointer(&cdevinfo.IssuerName[0]))
	godevinfo.DeviceName = *(*[16]byte)(unsafe.Pointer(&cdevinfo.DeviceName[0]))
	godevinfo.DeviceSerial = *(*[16]byte)(unsafe.Pointer(&cdevinfo.DeviceSerial[0]))
	godevinfo.DeviceVersion = uint(cdevinfo.DeviceVersion)
	godevinfo.StandardVersion = uint(cdevinfo.StandardVersion)
	godevinfo.AsymAlgAbility[0] = uint(cdevinfo.AsymAlgAbility[0])
	godevinfo.AsymAlgAbility[1] = uint(cdevinfo.AsymAlgAbility[1])
	godevinfo.SymAlgAbility = uint(cdevinfo.SymAlgAbility)
	godevinfo.HashAlgAbility = uint(cdevinfo.HashAlgAbility)
	godevinfo.BufferSize = uint(cdevinfo.BufferSize)
	return &godevinfo
}

func ConvertToRSArefPublicKeyGo(crsapubkeyst *C.RSArefPublicKey) *RSArefPublicKey {
	if crsapubkeyst == nil {
		return nil
	}
	var gorsapubkeyst RSArefPublicKey
	gorsapubkeyst.Bits = uint(crsapubkeyst.bits)

	gorsapubkeyst.E = *(*[LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&crsapubkeyst.e[0]))
	gorsapubkeyst.M = *(*[LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&crsapubkeyst.m[0]))

	return &gorsapubkeyst
}

func ConvertToRSArefPrivateKeyGo(crsaprivkeyst *C.RSArefPrivateKey) *RSArefPrivateKey {
	if crsaprivkeyst == nil {
		return nil
	}
	var gorsaprivkeyst RSArefPrivateKey
	gorsaprivkeyst.Bits = uint(crsaprivkeyst.bits)

	gorsaprivkeyst.E = *(*[LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&crsaprivkeyst.e[0]))
	gorsaprivkeyst.M = *(*[LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&crsaprivkeyst.m[0]))
	gorsaprivkeyst.D = *(*[LiteRSAref_MAX_LEN]byte)(unsafe.Pointer(&crsaprivkeyst.d[0]))
	gorsaprivkeyst.Prime[0] = *(*[LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&crsaprivkeyst.prime[0][0]))
	gorsaprivkeyst.Prime[1] = *(*[LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&crsaprivkeyst.prime[1][0]))
	gorsaprivkeyst.Pexp[0] = *(*[LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&crsaprivkeyst.pexp[0][0]))
	gorsaprivkeyst.Pexp[1] = *(*[LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&crsaprivkeyst.pexp[1][0]))
	gorsaprivkeyst.Coef = *(*[LiteRSAref_MAX_PLEN]byte)(unsafe.Pointer(&crsaprivkeyst.coef))

	return &gorsaprivkeyst
}

func ConvertToRSArefPublicKeyC(publicKey *RSArefPublicKey) *C.RSArefPublicKey {
	if publicKey == nil {
		return nil
	}
	var pucPublicKey C.RSArefPublicKey
	pucPublicKey.bits = C.uint(publicKey.Bits)
	pucPublicKey.m = *(*[LiteRSAref_MAX_LEN]C.uchar)(unsafe.Pointer(&publicKey.M[0]))
	pucPublicKey.e = *(*[LiteRSAref_MAX_LEN]C.uchar)(unsafe.Pointer(&publicKey.E[0]))

	return &pucPublicKey
}

func ConvertToRSArefPrivateKeyC(privateKey *RSArefPrivateKey) *C.RSArefPrivateKey {
	if privateKey == nil {
		return nil
	}
	var pucPrivateKey C.RSArefPrivateKey
	pucPrivateKey.bits = C.uint(privateKey.Bits)
	pucPrivateKey.m = *(*[LiteRSAref_MAX_LEN]C.uchar)(unsafe.Pointer(&privateKey.M[0]))
	pucPrivateKey.e = *(*[LiteRSAref_MAX_LEN]C.uchar)(unsafe.Pointer(&privateKey.E[0]))
	pucPrivateKey.d = *(*[LiteRSAref_MAX_LEN]C.uchar)(unsafe.Pointer(&privateKey.D[0]))
	pucPrivateKey.prime[0] = *(*[LiteRSAref_MAX_PLEN]C.uchar)(unsafe.Pointer(&privateKey.Prime[0][0]))
	pucPrivateKey.prime[1] = *(*[LiteRSAref_MAX_PLEN]C.uchar)(unsafe.Pointer(&privateKey.Prime[1][0]))
	pucPrivateKey.pexp[0] = *(*[LiteRSAref_MAX_PLEN]C.uchar)(unsafe.Pointer(&privateKey.Pexp[0][0]))
	pucPrivateKey.pexp[1] = *(*[LiteRSAref_MAX_PLEN]C.uchar)(unsafe.Pointer(&privateKey.Pexp[1][0]))
	pucPrivateKey.coef = *(*[LiteRSAref_MAX_PLEN]C.uchar)(unsafe.Pointer(&privateKey.Coef[0]))

	// for i := 0; i < len(privateKey.M); i++ {
	// 	pucPrivateKey.m[i] = C.uchar(privateKey.M[i])
	// }
	// for i := 0; i < len(privateKey.E); i++ {
	// 	pucPrivateKey.e[i] = C.uchar(privateKey.E[i])
	// }
	// for i := 0; i < len(privateKey.D); i++ {
	// 	pucPrivateKey.d[i] = C.uchar(privateKey.D[i])
	// }
	// for i := 0; i < len(privateKey.Coef); i++ {
	// 	pucPrivateKey.coef[i] = C.uchar(privateKey.Coef[i])
	// }
	// for i := 0; i < len(privateKey.Prime[0]); i++ {
	// 	pucPrivateKey.prime[0][i] = C.uchar(privateKey.Prime[0][i])
	// }
	// for i := 0; i < len(privateKey.Prime[0]); i++ {
	// 	pucPrivateKey.prime[1][i] = C.uchar(privateKey.Prime[1][i])
	// }
	// for i := 0; i < len(privateKey.Pexp[0]); i++ {
	// 	pucPrivateKey.pexp[0][i] = C.uchar(privateKey.Pexp[0][i])
	// }
	// for i := 0; i < len(privateKey.Pexp[0]); i++ {
	// 	pucPrivateKey.pexp[1][i] = C.uchar(privateKey.Pexp[1][i])
	// }

	return &pucPrivateKey
}

func ConvertToECCrefPublicKeyC(publicKey *ECCrefPublicKey) *C.ECCrefPublicKey {
	if publicKey == nil {
		return nil
	}
	var pucPublicKey C.ECCrefPublicKey
	pucPublicKey.bits = C.uint(publicKey.Bits)
	pucPublicKey.x = *(*[ECCref_MAX_LEN]C.uchar)(unsafe.Pointer(&publicKey.X[0]))
	pucPublicKey.y = *(*[ECCref_MAX_LEN]C.uchar)(unsafe.Pointer(&publicKey.Y[0]))

	// for i := 0; i < len(publicKey.X); i++ {
	// 	pucPublicKey.x[i] = C.uchar(publicKey.X[i])
	// }
	// for i := 0; i < len(publicKey.Y); i++ {
	// 	pucPublicKey.y[i] = C.uchar(publicKey.Y[i])
	// }

	return &pucPublicKey
}

func ConvertToECCrefPublicKeyGo(pucPublicKey *C.ECCrefPublicKey) *ECCrefPublicKey {
	if pucPublicKey == nil {
		return nil
	}
	publicKey := ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X:    *(*[ECCref_MAX_LEN]byte)(unsafe.Pointer(&pucPublicKey.x[0])),
		Y:    *(*[ECCref_MAX_LEN]byte)(unsafe.Pointer(&pucPublicKey.y[0])),
	}
	return &publicKey
}

func ConvertToECCrefPrivateKeyC(privateKey *ECCrefPrivateKey) *C.ECCrefPrivateKey {
	if privateKey == nil {
		return nil
	}
	var pucPrivateKey C.ECCrefPrivateKey
	pucPrivateKey.bits = C.uint(privateKey.Bits)
	pucPrivateKey.K = *(*[ECCref_MAX_LEN]C.uchar)(unsafe.Pointer(&privateKey.K[0]))

	// for i := 0; i < len(privateKey.K); i++ {
	// 	pucPrivateKey.K[i] = C.uchar(privateKey.K[i])
	// }

	return &pucPrivateKey
}

func ConvertToECCrefPrivateKeyGo(pucPrivateKey *C.ECCrefPrivateKey) *ECCrefPrivateKey {
	if pucPrivateKey == nil {
		return nil
	}

	privateKey := ECCrefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		K:    *(*[ECCref_MAX_LEN]byte)(unsafe.Pointer(&pucPrivateKey.K[0])),
	}

	return &privateKey
}

func ConvertToECCCipherC(encData *ECCCipher) *C.ECCCipher {
	if encData == nil {
		return nil
	}
	var pucEncData C.ECCCipher
	pucEncData.L = C.uint(encData.L)
	pucEncData.x = *(*[ECCref_MAX_LEN]C.uchar)(unsafe.Pointer(&encData.X[0]))
	pucEncData.y = *(*[ECCref_MAX_LEN]C.uchar)(unsafe.Pointer(&encData.Y[0]))
	pucEncData.M = *(*[32]C.uchar)(unsafe.Pointer(&encData.M[0]))
	pucEncData.C = *(*[ECCref_CIPHER_LEN]C.uchar)(unsafe.Pointer(&encData.C[0]))

	// for i := 0; i < len(encData.X); i++ {
	// 	pucEncData.x[i] = C.uchar(encData.X[i])
	// 	pucEncData.y[i] = C.uchar(encData.Y[i])
	// }
	// for i := 0; i < len(encData.M); i++ {
	// 	pucEncData.M[i] = C.uchar(encData.M[i])
	// }
	// for i := 0; i < int(encData.L); i++ {
	// 	pucEncData.C[i] = C.uchar(encData.C[i])
	// }

	return &pucEncData
}

func ConvertToECCCipherGo(pucKey *C.ECCCipher) *ECCCipher {
	if pucKey == nil {
		return nil
	}
	key := ECCCipher{
		X: *(*[ECCref_MAX_LEN]byte)(unsafe.Pointer(&pucKey.x[0])),
		Y: *(*[ECCref_MAX_LEN]byte)(unsafe.Pointer(&pucKey.y[0])),
		M: *(*[SM3ResultMaxLen]byte)(unsafe.Pointer(&pucKey.M[0])),
		L: uint(pucKey.L),
		C: *(*[ECCref_CIPHER_LEN]byte)(unsafe.Pointer(&pucKey.C[0])),
	}

	return &key
}

func ConvertToECCSignatureC(signature *ECCSignature) *C.ECCSignature {
	if signature == nil {
		return nil
	}
	var pSignature C.ECCSignature
	pSignature.r = *(*[ECCref_MAX_LEN]C.uchar)(unsafe.Pointer(&signature.R[0]))
	pSignature.s = *(*[ECCref_MAX_LEN]C.uchar)(unsafe.Pointer(&signature.S[0]))

	// for i := 0; i < len(signature.R); i++ {
	// 	pSignature.r[i] = C.uchar(signature.R[i])
	// }
	// for i := 0; i < len(signature.S); i++ {
	// 	pSignature.s[i] = C.uchar(signature.S[i])
	// }

	return &pSignature
}

func ConvertToECCSignatureGo(pucSignature *C.ECCSignature) *ECCSignature {
	if pucSignature == nil {
		return nil
	}
	signature := ECCSignature{
		R: *(*[ECCref_MAX_LEN]byte)(unsafe.Pointer(&pucSignature.r[0])),
		S: *(*[ECCref_MAX_LEN]byte)(unsafe.Pointer(&pucSignature.s[0])),
	}

	return &signature
}

// // 计算 (privateKey + 1) 的模反数
// func (priv *sm2.PrivateKey) inverseOfKeyPlus1Calc() *big.Int {
// 	priv.inverseOfKeyPlus1Once.Do(func() {
// 		priv.inverseOfKeyPlus1 = bigmod.Inverse(bigmod.Add(priv.D, big.NewInt(1)), priv.PublicKey.Curve.Params().N)
// 	})
// 	return priv.inverseOfKeyPlus1
// }
