package ISDF

/*
#cgo CFLAGS: -I ./inc/
#cgo LDFLAGS:
#include "sdf.h"
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

func OpenDevice() (unsafe.Pointer, int) {
	var devh unsafe.Pointer = nil
	uiret := C.SDF_OpenDevice(&devh)
	return devh, int(uiret)
}

func CloseDevice(devh unsafe.Pointer) int {
	return int(C.SDF_CloseDevice(devh))
}

func OpenSession(devh unsafe.Pointer) (unsafe.Pointer, int) {
	var sesh unsafe.Pointer
	uiret := C.SDF_OpenSession(devh, &sesh)
	return sesh, int(uiret)
}

func CloseSession(sesh unsafe.Pointer) int {
	return int(C.SDF_CloseSession(sesh))
}

func GetDeviceInfo(sesh unsafe.Pointer) (*DeviceInof, int) {
	var uiret C.int
	var devinf C.DEVICEINFO
	uiret = C.SDF_GetDeviceInfo(sesh, &devinf)
	return ConvertToDevinfoGO(&devinf), int(uiret)
}

func GenerateRandom(sesh unsafe.Pointer, len int) ([]byte, int) {
	var random = make([]byte, len)
	uiret := C.SDF_GenerateRandom(sesh, C.uint(len),
		(*C.uchar)(unsafe.Pointer(&random[0])))
	return random, int(uiret)
}

func GetPrivateKeyAccessRight(sesh unsafe.Pointer, keyidx int, pwd []byte) int {
	return int(C.SDF_GetPrivateKeyAccessRight(sesh, C.uint(keyidx),
		(*C.uchar)(unsafe.Pointer(&pwd[0])), C.uint(len(pwd))))
}

func ReleasePrivateKeyAccessRight(sesh unsafe.Pointer, keyidx int) int {
	return int(C.SDF_ReleasePrivateKeyAccessRight(sesh, C.uint(keyidx)))
}

func ExportSignPublicKeyRSA(sesh unsafe.Pointer, keyidx int) (*RSArefPublicKey, int) {
	var crpubk C.RSArefPublicKey
	uiret := C.SDF_ExportSignPublicKey_RSA(sesh, C.uint(keyidx), &crpubk)
	return ConvertToRSArefPublicKeyGo(&crpubk), int(uiret)
}

func ExportEncPublicKeyRSA(sesh unsafe.Pointer, keyidx int) (*RSArefPublicKey, int) {
	var crpubk C.RSArefPublicKey
	uiret := C.SDF_ExportEncPublicKey_RSA(sesh, C.uint(keyidx), &crpubk)
	return ConvertToRSArefPublicKeyGo(&crpubk), int(uiret)
}

func GenerateKeyPairRSA(sesh unsafe.Pointer, keybits int) (
	*RSArefPublicKey, *RSArefPrivateKey, int) {
	var crpubk C.RSArefPublicKey
	var cprivk C.RSArefPrivateKey
	uiret := C.SDF_GenerateKeyPair_RSA(sesh, C.uint(keybits), &crpubk, &cprivk)
	return ConvertToRSArefPublicKeyGo(&crpubk),
		ConvertToRSArefPrivateKeyGo(&cprivk), int(uiret)
}

func GenerateKeyPairECC(sesh unsafe.Pointer, algid int, keybits int) (
	*ECCrefPublicKey, *ECCrefPrivateKey, int) {
	var cepubk C.ECCrefPublicKey
	var cerivk C.ECCrefPrivateKey
	uiret := C.SDF_GenerateKeyPair_ECC(sesh, C.uint(algid), C.uint(keybits), &cepubk, &cerivk)
	return ConvertToECCrefPublicKeyGo(&cepubk), ConvertToECCrefPrivateKeyGo(&cerivk), int(uiret)
}

func ImportKey(sesh unsafe.Pointer, key []byte) (unsafe.Pointer, int) {
	var keyh unsafe.Pointer
	uiret := C.SDF_ImportKey(sesh, (*C.uchar)(unsafe.Pointer(&key[0])),
		C.uint(len(key)), &keyh)
	return keyh, int(uiret)
}

func DestroyKey(sesh unsafe.Pointer, keyh unsafe.Pointer) int {
	return int(C.SDF_DestroyKey(sesh, keyh))
}

func ExternalPublicKeyOperationRSA(sesh unsafe.Pointer,
	rpubk *RSArefPublicKey, data []byte) ([]byte, int) {
	var outdata = make([]byte, rpubk.Bits/8)
	var outlen C.uint
	uiret := C.SDF_ExternalPublicKeyOperation_RSA(sesh,
		ConvertToRSArefPublicKeyC(rpubk), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)), (*C.uchar)(unsafe.Pointer(&outdata[0])), &outlen)
	return outdata, int(uiret)
}

func ExternalVerifyECC(sesh unsafe.Pointer, algid int,
	ecpubk *ECCrefPublicKey, data []byte, ecsig *ECCSignature) int {
	return int(C.SDF_ExternalVerify_ECC(sesh, C.uint(algid),
		ConvertToECCrefPublicKeyC(ecpubk), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)), ConvertToECCSignatureC(ecsig)))
}

func ExternalEncryptECC(sesh unsafe.Pointer, algid int,
	ecpubk *ECCrefPublicKey, data []byte) (*ECCCipher, int) {
	var cecip C.ECCCipher
	uiret := C.SDF_ExternalEncrypt_ECC(sesh, C.uint(algid),
		ConvertToECCrefPublicKeyC(ecpubk), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)), &cecip)
	return ConvertToECCCipherGo(&cecip), int(uiret)
}

func Encrypt(sesh unsafe.Pointer, keyh unsafe.Pointer, algid int,
	iv []byte, data []byte) ([]byte, int) {
	var uiret C.int
	var outdata = make([]byte, len(data))
	var outdatalen C.uint
	if iv == nil {
		uiret = C.SDF_Encrypt(sesh, keyh, C.uint(algid), nil,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	} else {
		uiret = C.SDF_Encrypt(sesh, keyh, C.uint(algid), (*C.uchar)(unsafe.Pointer(&iv[0])),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	}
	return outdata, int(uiret)
}

func EncryptEx(sesh unsafe.Pointer, key []byte, algid int,
	iv []byte, data []byte) ([]byte, int) {
	var uiret C.int
	var outdata = make([]byte, len(data))
	var outdatalen C.uint
	var keyh unsafe.Pointer
	uiret = C.SDF_ImportKey(sesh, (*C.uchar)(unsafe.Pointer(&key[0])),
		C.uint(len(key)), &keyh)
	if uiret != 0 {
		return nil, int(uiret)
	}
	defer C.SDF_DestroyKey(sesh, keyh)

	if iv == nil {
		uiret = C.SDF_Encrypt(sesh, keyh, C.uint(algid), nil,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	} else {
		uiret = C.SDF_Encrypt(sesh, keyh, C.uint(algid), (*C.uchar)(unsafe.Pointer(&iv[0])),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	}
	return outdata, int(uiret)
}

func Decrypt(sesh unsafe.Pointer, keyh unsafe.Pointer, algid int,
	iv []byte, data []byte) ([]byte, int) {
	var uiret C.int
	var outdata = make([]byte, len(data))
	var outdatalen C.uint
	if iv == nil {
		uiret = C.SDF_Decrypt(sesh, keyh, C.uint(algid), nil,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	} else {
		uiret = C.SDF_Decrypt(sesh, keyh, C.uint(algid), (*C.uchar)(unsafe.Pointer(&iv[0])),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	}
	return outdata, int(uiret)
}

func DecryptEx(sesh unsafe.Pointer, key []byte, algid int,
	iv []byte, data []byte) ([]byte, int) {
	var uiret C.int
	var outdata = make([]byte, len(data))
	var outdatalen C.uint
	var keyh unsafe.Pointer
	uiret = C.SDF_ImportKey(sesh, (*C.uchar)(unsafe.Pointer(&key[0])),
		C.uint(len(key)), &keyh)
	if uiret != 0 {
		return nil, int(uiret)
	}
	defer C.SDF_DestroyKey(sesh, keyh)

	if iv == nil {
		uiret = C.SDF_Decrypt(sesh, keyh, C.uint(algid), nil,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	} else {
		uiret = C.SDF_Decrypt(sesh, keyh, C.uint(algid), (*C.uchar)(unsafe.Pointer(&iv[0])),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data)),
			(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	}
	return outdata, int(uiret)
}

func HashInit(sesh unsafe.Pointer, algid int,
	ecpubk *ECCrefPublicKey, id []byte) int {
	var iret C.int
	if ecpubk == nil || id == nil {
		iret = C.SDF_HashInit(sesh, C.uint(algid), nil,
			nil, 0)
	} else {
		iret = C.SDF_HashInit(sesh, C.uint(algid),
			ConvertToECCrefPublicKeyC(ecpubk),
			(*C.uchar)(unsafe.Pointer(&id[0])), C.uint(len(id)))
	}
	return int(iret)
}

func HashUpdate(sesh unsafe.Pointer, data []byte) int {
	return int(C.SDF_HashUpdate(sesh,
		(*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data))))
}

func HashFinal(sesh unsafe.Pointer) ([]byte, int) {
	var uiret C.int
	var outdata = make([]byte, 32)
	var outdatalen C.uint
	uiret = C.SDF_HashFinal(sesh,
		(*C.uchar)(unsafe.Pointer(&outdata[0])), &outdatalen)
	return outdata, int(uiret)
}

func Hash(sesh unsafe.Pointer, data []byte) ([]byte, int) {
	uiret := HashInit(sesh, SGD_SM3, nil, nil)
	if uiret != 0 {
		return nil, uiret
	}

	uiret = HashUpdate(sesh, data)
	if uiret != 0 {
		return nil, uiret
	}

	return HashFinal(sesh)
}

const SDR_CREATEFILE = 0x01000016
const SDFFILEDIR = "../createdFile"

func CreateFile(sesh unsafe.Pointer, fileName []byte, fileSize int) int {
	if err := os.MkdirAll(SDFFILEDIR, os.ModePerm); err != nil {
		fmt.Println("Error creating directory:", err)
		return SDR_CREATEFILE
	}

	filePath := filepath.Join(SDFFILEDIR, string(fileName))

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		fmt.Println("Error: File already exists")
		return SDR_CREATEFILE
	}

	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return SDR_CREATEFILE
	}
	defer file.Close()

	content := make([]byte, fileSize)
	if _, err := file.Write(content); err != nil {
		fmt.Println("Error writing to file:", err)
		return SDR_CREATEFILE
	}

	return 0
}

const SDR_READFILE = 0x01000017

func ReadFile(sesh unsafe.Pointer, fileName []byte, offset int, readLen int) ([]byte, int) {
	filePath := filepath.Join(SDFFILEDIR, string(fileName))

	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return nil, SDR_READFILE
	}

	if offset+readLen > len(content) {
		readLen = len(content) - offset
	}

	if offset > len(content) {
		fmt.Println("Error: Offset is beyond file size")
		return nil, SDR_READFILE
	}

	data := content[offset : offset+readLen]
	return data, 0
}

const SDR_WRITEFILE = 0x01000017

func WriteFile(sesh unsafe.Pointer, fileName []byte, offset int, data []byte) int {
	filePath := filepath.Join(SDFFILEDIR, string(fileName))
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0644)
	if err != nil {
		return SDR_WRITEFILE
	}
	defer file.Close()

	ff, _ := os.Stat(filePath)

	if offset+len(data) > int(ff.Size()) {
		return SDR_WRITEFILE
	}

	_, err = file.Seek(int64(offset), 0)
	if err != nil {
		return SDR_WRITEFILE
	}

	_, err = file.Write(data)
	if err != nil {
		return SDR_WRITEFILE
	}
	return 0
}

func DeleteFile(sesh unsafe.Pointer, fileName []byte) int {
	filePath := filepath.Join(SDFFILEDIR, string(fileName))
	os.Remove(filePath)
	return 0
}

func GenerateKeyWithKEK(sesh unsafe.Pointer, keybits uint,
	algid uint, keyidx uint) ([]byte, unsafe.Pointer, int) {
	var outputkey []byte = make([]byte, 1024)
	var outputkeylen C.uint
	var keyh unsafe.Pointer
	iret := C.SDF_GenerateKeyWithKEK(sesh, C.uint(keybits), C.uint(algid),
		C.uint(keyidx), (*C.uchar)(unsafe.Pointer(&outputkey[0])), &outputkeylen, &keyh)
	if iret != 0 {
		return nil, nil, int(iret)
	} else {
		return outputkey[:outputkeylen], keyh, 0
	}
}

func ImportKeyWithKEK(sesh unsafe.Pointer,
	algid uint, keyidx uint, ekey []byte) (unsafe.Pointer, int) {
	var keyh unsafe.Pointer
	iret := C.SDF_ImportKeyWithKEK(sesh, C.uint(algid), C.uint(keyidx),
		(*C.uchar)(unsafe.Pointer(&ekey[0])), C.uint(len(ekey)), &keyh)
	if iret != 0 {
		return nil, int(iret)
	} else {
		return keyh, 0
	}
}
