package sv0029_asn1

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

const VersionDefault = 0

const SGD_SM3_RSA = 0x00010001
const SGD_SHA1_RSA = 0x00010002
const SGD_SHA256_RSA = 0x00010004
const SGD_SM3_SM2 = 0x00020201

const VefifySignDataRequestType_Cert = 1
const VefifySignDataRequestType_Serial = 2

const VefifySignDataRequestType_VfyLevelTime = 0
const VefifySignDataRequestType_VfyLevelSig = 1
const VefifySignDataRequestType_VfyLevelAll = 2

const (
	SGD_CERT_VERSION                    = 0x00000001 // 证书版本
	SGD_CERT_SERIAL                     = 0x00000002 // 证书序列号
	SGD_CERT_ISSUER                     = 0x00000005 // 证书颁发者信息
	SGD_CERT_VALID_TIME                 = 0x00000006 // 证书有效期
	SGD_CERT_SUBJECT                    = 0x00000007 // 证书拥有者信息
	SGD_CERT_DER_PUBLIC_KEY             = 0x00000008 // 证书公钥信息
	SGD_CERT_DER_EXTENSIONS             = 0x00000009 // 证书扩展项目信息
	SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO = 0x00000011 // 颁发者密钥标识符
	SGD_EXT_SUBJECTKEYIDENTIFIER_INFO   = 0x00000012 // 证书持有者密钥标识符
	SGD_EXT_KEYUSAGE_INFO               = 0x00000013 // 密钥用途
	SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO  = 0x00000014 // 私钥有效期
	SGD_EXT_CERTIFICATEPOLICIES_INFO    = 0x00000015 // 证书策略
	SGD_EXT_POLICYMAPPINGS_INFO         = 0x00000016 // 策略映射
	SGD_EXT_BASICCONSTRAINTS_INFO       = 0x00000017 // 基本限制
	SGD_EXT_POLICYCONSTRAINTS_INFO      = 0x00000018 // 策略限制
	SGD_EXT_EXTKEYUSAGE_INFO            = 0x00000019 // 扩展密钥用途
	SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO  = 0x0000001A // CRL发布点
	SGD_EXT_NETSCAPE_CERT_TYPE_INFO     = 0x0000001B // Netscape属性
	SGD_EXT_SELF_DEFINED_EXTENSION_INFO = 0x0000001C // 私有的自定义扩展项
	SGD_CERT_ISSUER_CN                  = 0x00000021 // 证书颁发者CN
	SGD_CERT_ISSUER_O                   = 0x00000022 // 证书颁发者O
	SGD_CERT_ISSUER_OU                  = 0x00000023 // 证书颁发者OU
	SGD_CERT_SUBJECT_CN                 = 0x00000031 // 证书拥有者信息CN
	SGD_CERT_SUBJECT_O                  = 0x00000032 // 证书拥有者信息O
	SGD_CERT_SUBJECT_OU                 = 0x00000033 // 证书拥有者信息OU
	SGD_CERT_SUBJECT_EMAIL              = 0x00000034 // 证书拥有者信息EMAIL
	SGD_CERT_NOTBEFORE_TIME             = 0x00000035 // 证书起始日期
	SGD_CERT_NOTAFTER_TIME              = 0x00000036 // 证书截至日期
)

type Bs asn1.BitString

// Sig
type SM2Signature struct {
	R *big.Int `asn1:"integer"`
	S *big.Int `asn1:"integer"`
}

// Cert Type
type CertT_Version struct {
	Version int `asn1:"explicit,tag:0"`
}

type CertT_Serial struct {
	Number []byte `asn1:"integer"`
}

type CertT_Issuer struct {
	Raw []byte `asn1:"tag:3"`
}

type CertT_Validity struct {
	NotBefore time.Time `asn1:"generalized"`
	NotAfter  time.Time `asn1:"generalized"`
}

type CertT_Subject struct {
	Raw []byte `asn1:"tag:4"`
}

type CertT_PubKey struct {
	Raw []byte `asn1:"tag:5"`
}

type CertT_Extensions struct {
	Raw []byte `asn1:"tag:6"`
}

type CertT_AuthKeyID struct {
	ID []byte `asn1:"tag:11"`
}

type CertT_SubjKeyID struct {
	ID []byte `asn1:"tag:12"`
}

type CertT_KeyUsage struct {
	Bits Bs `asn1:"tag:13"`
}

type CertT_BasicConstraints struct {
	IsCA       bool `asn1:"tag:20"`
	MaxPathLen int  `asn1:"optional,tag:21"`
}

type CertT_ExtKeyUsage struct {
	OIDs []int `asn1:"tag:25"`
}

type CertT_IssuerCN struct {
	CN string `asn1:"utf8,tag:33"`
}

type CertT_IssuerO struct {
	O string `asn1:"utf8,tag:34"`
}

type CertT_SubjectCN struct {
	CN string `asn1:"utf8,tag:49"`
}

type CertT_SubjectEmail struct {
	Email string `asn1:"ia5,tag:52"`
}

type CertT_NotBefore struct {
	Time time.Time `asn1:"generalized,tag:53"`
}

type CertT_NotAfter struct {
	Time time.Time `asn1:"generalized,tag:54"`
}

// ExFunc
// pad BigInt
func PadBigInt(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// Decode SM2Signature
func Decode_asn1RawSM2Sig_2_bSM2Sig(rawSig asn1.RawValue) ([]byte, error) {
	var sig SM2Signature
	_, err := asn1.Unmarshal(rawSig.Bytes, &sig)
	if err != nil {
		return nil, fmt.Errorf("Decode SM2Signature ASN.1 Error[%s]", err)
	}

	// 将R和S转换为固定32字节（大端序）
	rBytes := PadBigInt(sig.R, 32)
	sBytes := PadBigInt(sig.S, 32)
	return append(rBytes, sBytes...), nil
}

// sig len 64 r:[0:32] s:[32:64]
func Encode_bSM2Sig_2_asn1RawSM2sig(sig []byte, tag int) (asn1.RawValue, error) {
	len := len(sig)
	if len != 64 {
		return asn1.RawValue{}, fmt.Errorf("Signature Type Error")
	}
	var sm2sig SM2Signature
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	sm2sig.R = r
	sm2sig.S = s

	encodesm2_sig, err := asn1.Marshal(sm2sig)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("Signature Type Error")
	}

	rawsig := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      encodesm2_sig,
	}

	return rawsig, nil
}

func Marshal(val any) ([]byte, error) {
	return asn1.Marshal(val)
}

func UnMarshal(b []byte, val any) (rest []byte, err error) {
	return asn1.Unmarshal(b, val)
}
