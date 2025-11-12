package ISDF

/*
#cgo CFLAGS: -I ./inc/
#cgo LDFLAGS: -L ./lib  -Wl,-rpath=./lib -lsoftsdf
#include "sdf.h"
*/
import "C"

const (
	SGD_TRUE      = 0x00000001
	SGD_FALSE     = 0x00000000
	SGD_SM1_ECB   = 0x00000101
	SGD_SM1_CBC   = 0x00000102
	SGD_SM1_CFB   = 0x00000104
	SGD_SM1_OFB   = 0x00000108
	SGD_SM1_MAC   = 0x00000110
	SGD_SM1_CTR   = 0x00000120
	SGD_SSF33_ECB = 0x00000201
	SGD_SSF33_CBC = 0x00000202
	SGD_SSF33_CFB = 0x00000204
	SGD_SSF33_OFB = 0x00000208
	SGD_SSF33_MAC = 0x00000210
	SGD_SSF33_CTR = 0x00000220
	SGD_SM4_ECB   = 0x00000401
	SGD_SM4_CBC   = 0x00000402
	SGD_SM4_CFB   = 0x00000404
	SGD_SM4_OFB   = 0x00000408
	SGD_SM4_MAC   = 0x00000410
	SGD_SM4_CTR   = 0x00000420
	SGD_3DES_ECB  = 0x00000801
	SGD_3DES_CBC  = 0x00000802
	SGD_3DES_CFB  = 0x00000804
	SGD_3DES_OFB  = 0x00000808
	SGD_3DES_MAC  = 0x00000810
	SGD_3DES_CTR  = 0x00000820
	SGD_AES_ECB   = 0x00002001
	SGD_AES_CBC   = 0x00002002
	SGD_AES_CFB   = 0x00002004
	SGD_AES_OFB   = 0x00002008
	SGD_AES_MAC   = 0x00002010
	SGD_AES_CTR   = 0x00002020
	SGD_RSA       = 0x00010000
	SGD_RSA_SIGN  = 0x00010100
	SGD_RSA_ENC   = 0x00010200
	SGD_SM2       = 0x00020100
	SGD_SM2_1     = 0x00020200
	SGD_SM2_2     = 0x00020400
	SGD_SM2_3     = 0x00020800
	SGD_SM9       = 0x00100000
	SGD_SM9_1     = 0x00100100
	SGD_SM9_2     = 0x00100200
	SGD_SM9_3     = 0x00100400
	SGD_SM9_4     = 0x00100800
	SGD_SM3       = 0x00000001
	SGD_SHA1      = 0x00000002
	SGD_SHA256    = 0x00000004
	SGD_SHA512    = 0x00000008
	SGD_SHA384    = 0x00000010
	SGD_SHA224    = 0x00000020
	SGD_MD5       = 0x00000080
)

type DeviceInof struct {
	IssuerName      [40]byte // 设备生产厂商名称
	DeviceName      [16]byte // 设备型号
	DeviceSerial    [16]byte // 设备编号
	DeviceVersion   uint     // 密码设备内部软件版本号
	StandardVersion uint     // 密码设备支持的接口规范版本号
	AsymAlgAbility  [2]uint  // （非对称算法）前四字节表示支持的算法；后四字节表示算法的最大模长
	SymAlgAbility   uint     // （对称算法）所有支持的对称算法
	HashAlgAbility  uint     // 所有支持的杂凑算法
	BufferSize      uint     // 支持的最大文件存储空间
}

const EccMaxEncDecLen uint = 4096
const RsaMaxEncDecLen uint = 4096
const SM3ResultMaxLen uint = 32

const LiteRSAref_MAX_BITS uint = uint(C.RSAref_MAX_BITS)
const LiteRSAref_MAX_LEN uint = ((LiteRSAref_MAX_BITS + 7) / 8)
const LiteRSAref_MAX_PBITS uint = ((LiteRSAref_MAX_BITS + 1) / 2)
const LiteRSAref_MAX_PLEN uint = ((LiteRSAref_MAX_PBITS + 7) / 8)

const ECCref_MAX_BITS uint = uint(C.ECCref_MAX_BITS)
const ECCref_MAX_LEN uint = ((ECCref_MAX_BITS + 7) / 8)
const ECCref_CIPHER_LEN uint = uint(C.ECCref_MAX_CIPHER_LEN)

type RSArefPublicKey struct {
	Bits uint
	M    [LiteRSAref_MAX_LEN]byte
	E    [LiteRSAref_MAX_LEN]byte
}

type RSArefPrivateKey struct {
	Bits  uint
	M     [LiteRSAref_MAX_LEN]byte
	E     [LiteRSAref_MAX_LEN]byte
	D     [LiteRSAref_MAX_LEN]byte
	Prime [2][LiteRSAref_MAX_PLEN]byte
	Pexp  [2][LiteRSAref_MAX_PLEN]byte
	Coef  [LiteRSAref_MAX_PLEN]byte
}

type ECCrefPublicKey struct {
	Bits uint
	X    [ECCref_MAX_LEN]byte
	Y    [ECCref_MAX_LEN]byte
}

type ECCrefPrivateKey struct {
	Bits uint
	K    [ECCref_MAX_LEN]byte
}

type ECCCipher struct {
	X [ECCref_MAX_LEN]byte
	Y [ECCref_MAX_LEN]byte
	M [SM3ResultMaxLen]byte
	L uint
	C [ECCref_CIPHER_LEN]byte
}

type ECCSignature struct {
	R [ECCref_MAX_LEN]byte
	S [ECCref_MAX_LEN]byte
}
