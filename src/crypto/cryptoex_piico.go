//go:build piico

package ISDF

/*
#cgo CFLAGS: -I ./inc/
#cgo LDFLAGS:
#include "sdf.h"
*/
import "C"
import "unsafe"

func GenKEK2Idx(sesh unsafe.Pointer, keyIdx int, keyLen int) int {
	return int(C.SPII_GenerateKEK(sesh, C.uint(keyIdx), C.uint(keyLen)))
}

func DeleteKEKByIdx(sesh unsafe.Pointer, keyIdx int) int {
	return int(C.SPII_DeleteKEK(sesh, C.uint(keyIdx)))
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
	algid = SGD_SM2_1
	uiret := C.SDF_ExternalSign_ECC(sesh, C.uint(algid), ConvertToECCrefPrivateKeyC(ecpivk),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)), &ecsig)
	return ConvertToECCSignatureGo(&ecsig), int(uiret)
}

func ExternalDecryptECC(sesh unsafe.Pointer, algid int, ecpivk *ECCrefPrivateKey, eccip *ECCCipher) ([]byte, int) {
	var outdata = make([]byte, eccip.L)
	var outdatalen C.uint
	algid = SGD_SM2_3
	uiret := C.SDF_ExternalDecrypt_ECC(sesh, C.uint(algid), ConvertToECCrefPrivateKeyC(ecpivk),
		ConvertToECCCipherC(eccip), (*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	return outdata, int(uiret)
}

func Sudo(sesh unsafe.Pointer) int {
	pswd := []byte("3.1415926")
	return int(C.SPII_LoadinWithPassword(sesh,
		(*C.uchar)(unsafe.Pointer(&pswd[0])), C.uint(9), C.uint(2)))
}
