package sv0029_asn1

import (
	"encoding/asn1"
	"time"
)

const (
	RespType_ExportCert int = iota
	RespType_ParseCert
	RespType_ValidateCert
	RespType_SignData
	RespType_VerifySignedData
	RespType_SignDataInit
	RespType_SignDataUpdate
	RespType_SignDataFinal
	RespType_VerifySignedDataInit
	RespType_VerifySignedDataUpdate
	RespType_VerifySignedDataFinal
	RespType_SignMessage
	RespType_VerifySignedMessage
	RespType_SignMessageInit
	RespType_SignMessageUpdate
	RespType_SignMessageFinal
	RespType_VerifySignedMessageInit
	RespType_VerifySignedMessageUpdate
	RespType_VerifySignedMessageFinal
)

var RespTypeTag = []int{
	RespType_ExportCert,
	RespType_ParseCert,
	RespType_ValidateCert,
	RespType_SignData,
	RespType_VerifySignedData,
	RespType_SignDataInit,
	RespType_SignDataUpdate,
	RespType_SignDataFinal,
	RespType_VerifySignedDataInit,
	RespType_VerifySignedDataUpdate,
	RespType_VerifySignedDataFinal,
	RespType_SignMessage,
	RespType_VerifySignedMessage,
	RespType_SignMessageInit,
	RespType_SignMessageUpdate,
	RespType_SignMessageFinal,
	RespType_VerifySignedMessageInit,
	RespType_VerifySignedMessageUpdate,
	RespType_VerifySignedMessageFinal,
}

type SVSRespond_1 struct {
	Version  int           `asn1:"default:0,explicit,tag:20"`
	RespType int           `asn1:"explicit,tag:21"`
	Respond  asn1.RawValue `asn1:"implicit,optional"`
	RespTime time.Time     `asn1:"generalized,utc,explicit,tag:22"`
}

// 5.1 导出证书
type Respond_ExportCert_2 struct {
	RespVaule int           `asn1:"explicit,tag:0" `
	Cert      asn1.RawValue `asn1:"optional,explicit,tag:1" `
}

// 5.2 解析证书
type Respond_ParseCert_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	Info      []byte `asn1:"optional,octet,explicit,tag:1" `
}

// 5.3 验证证书有效性
type Respond_ValidateCert_2 struct {
	RespVaule int `asn1:"explicit,tag:0" `
	State     int `asn1:"optional,explicit,tag:1" `
}

// 5.4 单包数字签名
type Respond_SignData_2 struct {
	RespVaule int           `asn1:"explicit,tag:0" `
	Signature asn1.RawValue `asn1:"optional,explicit,tag:1" `
}

// 5.5 单包验证数字签名
type Respond_VerifySignedData_2 struct {
	RespVaule int `asn1:"explicit,tag:0" `
}

// 5.6 多包数字签名初始化
type Respond_SignDataInit_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.7 多包数字签名更新
type Respond_SignDataUpdate_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.8 多包数字签名结束
type Respond_SignDataFinal_2 struct {
	RespVaule int           `asn1:"explicit,tag:0" `
	Signature asn1.RawValue `asn1:"optional,explicit,tag:1" `
}

// 5.9 多包验证数字签名初始化
type Respond_VerifySignedDataInit_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.10 多包验证数字签名更新
type Respond_VerifySignedDataUpdate_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.11 多包验证数字签名结束
type Respond_VerifySignedDataFinal_2 struct {
	RespVaule int `asn1:"explicit,tag:0" `
}

// 5.12 单包消息签名
// SignedData 结构
type SignedData struct {
	Version          int
	DigestAlgorithms asn1.ObjectIdentifier `asn1:"set,explicit,tag:2"`
	ContentInfo      SM2Signature          `asn1:"explicit,tag:3"`
	Certificates     []byte                `asn1:"optional,tag:0"`
	CRLs             []byte                `asn1:"optional,tag:1"`
	SignerInfos      []SignerInfo          `asn1:"set,explicit,tag:4"`
}

// SignerInfo 结构
type SignerInfo struct {
	Version                   int                   `asn1:"explicit,tag:2"`
	IssuerAndSerialNumber     []byte                `asn1:"explicit,tag:3"`
	DigestAlgorithm           asn1.ObjectIdentifier `asn1:"explicit,tag:4"`
	AuthenticatedAttributes   []byte                `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm asn1.ObjectIdentifier `asn1:"explicit,tag:5"`
	EncryptedDigest           SM2Signature          `asn1:"explicit,tag:6"`
	UnauthenticatedAttributes []byte                `asn1:"optional,tag:1"`
}

type Respond_SignMessage_2 struct {
	RespVaule     int    `asn1:"explicit,tag:0" `
	SignedMessage []byte `asn1:"optional,explicit,octet,tag:1" ` //DER RSA:PKCS#7 SM2:<<GMT 0010 8.1>>
}

// 5.13 单包验证消息签名
type Respond_VerifySignedMessage_2 struct {
	RespVaule int `asn1:"explicit,tag:0" `
}

// 5.14 多包消息签名初始化
type Respond_SignMessageInit_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.15 多包消息签名更新
type Respond_SignMessageUpdate_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.16 多包消息签名结束
type Respond_SignMessageFinal_2 struct {
	RespVaule     int    `asn1:"explicit,tag:0" `
	SignedMessage []byte `asn1:"optional,explicit,octet,tag:1" ` //DER RSA:PKCS#7 SM2:<<GMT 0010 8.1>>
}

// 5.17 多包验证消息签名初始化
type Respond_VerifySignedMessageInit_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.18 多包验证消息签名更新
type Respond_VerifySignedMessageUpdate_2 struct {
	RespVaule int    `asn1:"explicit,tag:0" `
	HashValue []byte `asn1:"optional,explicit,octet,tag:1" `
}

// 5.19 多包验证消息签名结束
type Respond_VerifySignedMessageFinal_2 struct {
	RespVaule int `asn1:"explicit,tag:0" `
}
