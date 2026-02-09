//go:build softsdf

package ISDF

/*
#cgo CFLAGS: -I ./inc/
#cgo LDFLAGS:
#include "sdf.h"
*/
import "C"

import (
	"unsafe"
)

func GenKEK2Idx(sesh unsafe.Pointer, keyIdx int, keyLen int) int {
	return int(C.SDF_GenerateSymKey2Idx(sesh, C.uint(keyIdx), C.uint(keyLen)))
}

func DeleteKEKByIdx(sesh unsafe.Pointer, keyIdx int) int {
	return int(C.SDF_DeleteSymKeyFromIdx(sesh, C.uint(keyIdx)))
}

func ExternalPrivateKeyOperationRSA(sesh unsafe.Pointer, rpivk *RSArefPrivateKey, data []byte) ([]byte, int) {
	var outdata = make([]byte, rpivk.Bits/8)
	var outlen C.uint
	uiret := C.SDF_ExternalPrivateKeyOperation_RSA(sesh, ConvertToRSArefPrivateKeyC(rpivk),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)), (*C.uchar)(unsafe.Pointer(&outdata[0])), &outlen)
	return outdata, int(uiret)
}

func ExternalSignECC(sesh unsafe.Pointer, algid int, ecpivk *ECCrefPrivateKey, data []byte) (*ECCSignature, int) {
	var ecsig C.ECCSignature
	uiret := C.SDF_ExternalSign_ECC(sesh, C.uint(algid), ConvertToECCrefPrivateKeyC(ecpivk),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)), &ecsig)
	return ConvertToECCSignatureGo(&ecsig), int(uiret)
}

func ExternalDecryptECC(sesh unsafe.Pointer, algid int, ecpivk *ECCrefPrivateKey, eccip *ECCCipher) ([]byte, int) {
	var outdata = make([]byte, eccip.L)
	var outdatalen C.uint
	uiret := C.SDF_ExternalDecrypt_ECC(sesh, C.uint(algid), ConvertToECCrefPrivateKeyC(ecpivk),
		ConvertToECCCipherC(eccip), (*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	return outdata, int(uiret)
}

func Sudo(sesh unsafe.Pointer) int {
	return 0
}
