package sv0029_asn1

import (
	"encoding/asn1"
	"time"
)

const (
	ReqType_ExportCert int = iota
	ReqType_ParseCert
	ReqType_ValidateCert
	ReqType_SignData
	ReqType_VerifySignedData
	ReqType_SignDataInit
	ReqType_SignDataUpdate
	ReqType_SignDataFinal
	ReqType_VerifySignedDataInit
	ReqType_VerifySignedDataUpdate
	ReqType_VerifySignedDataFinal
	ReqType_SignMessage
	ReqType_VerifySignedMessage
	ReqType_SignMessageInit
	ReqType_SignMessageUpdate
	ReqType_SignMessageFinal
	ReqType_VerifySignedMessageInit
	ReqType_VerifySignedMessageUpdate
	ReqType_VerifySignedMessageFinal
)

var ReqTypeTag = []int{
	ReqType_ExportCert,
	ReqType_ParseCert,
	ReqType_ValidateCert,
	ReqType_SignData,
	ReqType_VerifySignedData,
	ReqType_SignDataInit,
	ReqType_SignDataUpdate,
	ReqType_SignDataFinal,
	ReqType_VerifySignedDataInit,
	ReqType_VerifySignedDataUpdate,
	ReqType_VerifySignedDataFinal,
	ReqType_SignMessage,
	ReqType_VerifySignedMessage,
	ReqType_SignMessageInit,
	ReqType_SignMessageUpdate,
	ReqType_SignMessageFinal,
	ReqType_VerifySignedMessageInit,
	ReqType_VerifySignedMessageUpdate,
	ReqType_VerifySignedMessageFinal,
}

type SvsRequest_1 struct {
	Version int           `asn1:"default:0,explicit,tag:20"`
	ReqType int           `asn1:"explicit,tag:21"`
	Request asn1.RawValue `asn1:"implicit,optional"`
	ReqTime time.Time     `asn1:"generalized,utc,explicit,tag:22"`
}

// 5.1 导出证书
type Request_ExportCert_2 struct {
	Identification []byte `asn1:"explicit,tag:0" `
}

// 5.2 解析证书
type Request_ParseCert_2 struct {
	InfoType int           `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.3.4>>
	Cert     asn1.RawValue `asn1:"implicit,tag:1" `
}

// 5.3 验证证书有效性
type Request_ValidateCert_2 struct {
	Cert asn1.RawValue `asn1:"implicit,tag:0" `
	OCSP bool          `asn1:"explicit,tag:1" ` // default false
}

// 5.4 单包数字签名
type Request_SignData_2 struct {
	SignMethod int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	KeyIndex   int    `asn1:"explicit,tag:1" `
	KeyValue   []byte `asn1:"octet,explicit,tag:2" ` // privkey PIN
	InDataLen  int    `asn1:"explicit,tag:3" `
	InData     []byte `asn1:"octet,explicit,tag:4" `
}

// 5.5 单包验证数字签名
/*
	type 1/2 cert/srial
	level 0:timeOnly 1:time&&sign 2.time&&sign&&CRL
*/
type Request_VerifySignedData_2 struct {
	Type        int           `asn1:"explicit,tag:2"`
	Cert        asn1.RawValue `asn1:"optional,implicit,tag:0"`
	CertSN      asn1.RawValue `asn1:"optional,octet,implicit,tag:1"`
	InDataLen   int           `asn1:"explicit,tag:3"`
	InData      []byte        `asn1:"octet,explicit,tag:4"`
	Signature   asn1.RawValue `asn1:"implicit,tag:5"` // RSA:PKCS#1 SM2:<<GMT 0009 7.3>>
	VerifyLevel int           `asn1:"explicit,tag:6"`
}

// 5.6 多包数字签名初始化
type Request_SignDataInit_2 struct {
	SignMethod      int    `asn1:"explicit,tag:3" ` // <<GMT 0006 2012 5.2.4>>
	SignerPublicKey []byte `asn1:"octet,optional,implicit,tag:0" `
	SignerIDLen     int    `asn1:"optional,implicit,tag:1"`
	SignerID        []byte `asn1:"octet,optional,implicit,tag:2"`
	InDataLen       int    `asn1:"explicit,tag:4"`
	InData          []byte `asn1:"octet,explicit,tag:5"`
}

// 5.7 多包数字签名更新
type Request_SignDataUpdate_2 struct {
	SignMethod   int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	HashVauleLen int    `asn1:"explicit,tag:1" `
	HashVaule    []byte `asn1:"octet,explicit,tag:2"`
	InDataLen    int    `asn1:"explicit,tag:3"`
	InData       []byte `asn1:"octet,explicit,tag:4"`
}

// 5.8 多包数字签名结束
type Request_SignDataFinal_2 struct {
	SignMethod   int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	KeyIndex     int    `asn1:"explicit,tag:1" `
	KeyValue     []byte `asn1:"octet,explicit,tag:2" ` // privkey PIN
	HashVauleLen int    `asn1:"explicit,tag:3" `
	HashVaule    []byte `asn1:"octet,explicit,tag:4"`
}

// 5.9 多包验证数字签名初始化
type Request_VerifySignedDataInit_2 struct {
	SignMethod      int    `asn1:"explicit,tag:3" ` // <<GMT 0006 2012 5.2.4>>
	SignerPublicKey []byte `asn1:"octet,optional,implicit,tag:0" `
	SignerIDLen     int    `asn1:"optional,implicit,tag:1"`
	SignerID        []byte `asn1:"octet,optional,implicit,tag:2"`
	InDataLen       int    `asn1:"explicit,tag:4"`
	InData          []byte `asn1:"octet,explicit,tag:5"`
}

// 5.10 多包验证数字签名更新
type Request_VerifySignedDataUpdate_2 struct {
	SignMethod   int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	HashVauleLen int    `asn1:"explicit,tag:1" `
	HashVaule    []byte `asn1:"octet,explicit,tag:2"`
	InDataLen    int    `asn1:"explicit,tag:3"`
	InData       []byte `asn1:"octet,explicit,tag:4"`
}

// 5.11 多包验证数字签名结束
type Request_VerifySignedDataFinal_2 struct {
	SignMethod   int           `asn1:"explicit,tag:2" ` // <<GMT 0006 2012 5.2.4>>
	Type         int           `asn1:"explicit,tag:3"`
	Cert         asn1.RawValue `asn1:"optional,implicit,tag:0"`
	CertSN       asn1.RawValue `asn1:"optional,octet,implicit,tag:1"`
	HashValueLen int           `asn1:"explicit,tag:4"`
	HashValue    []byte        `asn1:"octet,explicit,tag:6"`
	Signature    asn1.RawValue `asn1:"implicit,tag:5"` // RSA:PKCS#1 SM2:<<GMT 0009 7.3>>
	VerifyLevel  int           `asn1:"explicit,tag:8"`
}

// 5.12 单包消息签名
type Request_SignMessage_2 struct {
	SignMethod               int    `asn1:"explicit,tag:5" ` // <<GMT 0006 2012 5.2.4>>
	KeyIndex                 int    `asn1:"explicit,tag:6" `
	KeyValue                 []byte `asn1:"octet,explicit,tag:7" ` // privkey PIN
	InDataLen                int    `asn1:"explicit,tag:8"`
	InData                   []byte `asn1:"octet,explicit,tag:9"`
	HashFlag                 bool   `asn1:"optional,implicit,tag:0,default:false"`
	OriginalText             bool   `asn1:"optional,implicit,tag:1,default:false"`
	CertificateChain         bool   `asn1:"optional,implicit,tag:2,default:false"`
	Crl                      bool   `asn1:"optional,implicit,tag:3,default:false"`
	AuthenticationAttributes bool   `asn1:"optional,implicit,tag:4,default:false"`
}

// 5.13 单包验证消息签名
type Request_VerifySignedMessage_2 struct {
	InDataLen                int    `asn1:"explicit,tag:5"`
	InData                   []byte `asn1:"octet,explicit,tag:6"`
	SignedMessage            []byte `asn1:"octet,explicit,tag:7"` //DER RSA:PKCS#7 SM2:<<GMT 0010 8.1>>
	HashFlag                 bool   `asn1:"optional,implicit,tag:0,default:false"`
	OriginalText             bool   `asn1:"optional,implicit,tag:1,default:false"`
	CertificateChain         bool   `asn1:"optional,implicit,tag:2,default:false"`
	Crl                      bool   `asn1:"optional,implicit,tag:3,default:false"`
	AuthenticationAttributes bool   `asn1:"optional,implicit,tag:4,default:false"`
}

// 5.14 多包消息签名初始化
type Request_SignMessageInit_2 struct {
	SignMethod      int    `asn1:"explicit,tag:3" ` // <<GMT 0006 2012 5.2.4>>
	SignerPublicKey []byte `asn1:"octet,optional,implicit,tag:0" `
	SignerIDLen     int    `asn1:"optional,implicit,tag:1"`
	SignerID        []byte `asn1:"octet,optional,implicit,tag:2"`
	InDataLen       int    `asn1:"explicit,tag:4"`
	InData          []byte `asn1:"octet,explicit,tag:5"`
}

// 5.15 多包消息签名更新
type Request_SignMessageUpdate_2 struct {
	SignMethod   int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	HashVauleLen int    `asn1:"explicit,tag:1" `
	HashVaule    []byte `asn1:"octet,explicit,tag:2"`
	InDataLen    int    `asn1:"explicit,tag:3"`
	InData       []byte `asn1:"octet,explicit,tag:4"`
}

// 5.16 多包消息签名结束
type Request_SignMessageFinal_2 struct {
	SignMethod   int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	KeyIndex     int    `asn1:"explicit,tag:1" `
	KeyValue     []byte `asn1:"octet,explicit,tag:2" ` // privkey PIN
	HashVauleLen int    `asn1:"explicit,tag:3" `
	HashVaule    []byte `asn1:"octet,explicit,tag:4"`
}

// 5.17 多包验证消息签名初始化
type Request_VerifySignedMessageInit_2 struct {
	SignMethod      int    `asn1:"explicit,tag:3" ` // <<GMT 0006 2012 5.2.4>>
	SignerPublicKey []byte `asn1:"octet,optional,implicit,tag:0" `
	SignerIDLen     int    `asn1:"optional,implicit,tag:1"`
	SignerID        []byte `asn1:"octet,optional,implicit,tag:2"`
	InDataLen       int    `asn1:"explicit,tag:4"`
	InData          []byte `asn1:"octet,explicit,tag:5"`
}

// 5.18 多包验证消息签名更新
type Request_VerifySignedMessageUpdate_2 struct {
	SignMethod   int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	HashVauleLen int    `asn1:"explicit,tag:1" `
	HashVaule    []byte `asn1:"octet,explicit,tag:2"`
	InDataLen    int    `asn1:"explicit,tag:3"`
	InData       []byte `asn1:"octet,explicit,tag:4"`
}

// 5.19 多包验证消息签名结束
type Request_VerifySignedMessageFinal_2 struct {
	SignMethod    int    `asn1:"explicit,tag:0" ` // <<GMT 0006 2012 5.2.4>>
	HashVauleLen  int    `asn1:"explicit,tag:1" `
	HashVaule     []byte `asn1:"octet,explicit,tag:2"`
	SignedMessage []byte `asn1:"explicit,tag:3"` //DER RSA:PKCS#7 SM2:<<GMT 0010 8.1>>
}
