package sv0029_asn1

import (
	"encoding/asn1"
	"fmt"
	"time"
)

type SVSRequestBuilder struct {
	Version int
}

func NewSVSRequestBuilder() *SVSRequestBuilder {
	return &SVSRequestBuilder{
		Version: VersionDefault,
	}
}

// 5.1 导出证书
func (b *SVSRequestBuilder) BuildExportCertRequest(identification []byte) ([]byte, error) {
	inner := Request_ExportCert_2{Identification: identification}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("ExportCertRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_ExportCert,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_ExportCert],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}
	return asn1.Marshal(req)
}

// 5.2 解析证书
func (b *SVSRequestBuilder) BuildParseCertRequest(infoType int, cert []byte) ([]byte, error) {
	inner := Request_ParseCert_2{
		InfoType: infoType,
		Cert: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      cert,
		},
	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("ParseCertRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_ParseCert,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_ParseCert],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.3 验证证书有效性
func (b *SVSRequestBuilder) BuildValidateCertRequest(cert []byte, checkOCSP bool) ([]byte, error) {
	inner := Request_ValidateCert_2{
		Cert: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      cert,
		},
		OCSP: checkOCSP,
	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("ValidateCertRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_ValidateCert,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_ValidateCert],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.4 单包数字签名
func (b *SVSRequestBuilder) BuildSignDataRequest(signMethod, keyIndex int, keyValue, inData []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("SignDataRequest SignMethod Type Error")
	}

	inner := Request_SignData_2{
		SignMethod: signMethod,
		KeyIndex:   keyIndex,
		KeyValue:   keyValue,
		InDataLen:  len(inData),
		InData:     inData,
	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignData,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignData],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.5 单包验证数字签名
/*
	type 1:cert	2:srial
	level 0:timeOnly	1:time&&sign	2.time&&sign&&CRL
*/
func (b *SVSRequestBuilder) BuildVerifySignedDataRequest(typev int, v, data, sig []byte, vfyLevel int) ([]byte, error) {
	if vfyLevel != VefifySignDataRequestType_VfyLevelTime &&
		vfyLevel != VefifySignDataRequestType_VfyLevelSig &&
		vfyLevel != VefifySignDataRequestType_VfyLevelAll {
		return nil, fmt.Errorf("VerifySignedDataRequest VerifyLevel Type Error")
	}

	rawsig, err := Encode_bSM2Sig_2_asn1RawSM2sig(sig, 5)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataRequest %s", err)
	}

	inner := Request_VerifySignedData_2{
		Type:        typev,
		InDataLen:   len(data),
		InData:      data,
		Signature:   rawsig,
		VerifyLevel: vfyLevel,
	}
	if typev == VefifySignDataRequestType_Cert {
		inner.Cert.Class = asn1.ClassContextSpecific
		inner.Cert.Tag = 0
		inner.Cert.IsCompound = true
		inner.Cert.Bytes = v
	} else if typev == VefifySignDataRequestType_Serial {
		inner.CertSN.Class = asn1.ClassContextSpecific
		inner.CertSN.Tag = 1
		inner.CertSN.IsCompound = false
		inner.CertSN.Bytes = v
	} else {
		return nil, fmt.Errorf("VerifySignedDataRequest Type Error")
	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataRequest Marshal Error[%s]", err)

	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedData,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedData],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.6 多包数字签名初始化
func (b *SVSRequestBuilder) BuildSignDataInitRequest(signMethod int, sPubK, sID, data []byte) ([]byte, error) {
	inner := Request_SignDataInit_2{}
	if signMethod == SGD_SM3_RSA ||
		signMethod == SGD_SM3_SM2 {

		inner.SignerPublicKey = sPubK
		inner.SignerIDLen = len(sID)
		inner.SignerID = sID

	} else if signMethod == SGD_SHA1_RSA ||
		signMethod == SGD_SHA256_RSA {

	} else {
		return nil, fmt.Errorf("SignDataInitRequest SignMethod Type Error")
	}
	inner.SignMethod = signMethod
	inner.InDataLen = len(data)
	inner.InData = data

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataInitRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignDataInit,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignDataInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.7 多包数字签名更新
func (b *SVSRequestBuilder) BuildSignDataUpdateRequest(signMethod int, hash, data []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("SignDataUpdateRequest SignMethod Type Error")
	}

	inner := Request_SignDataUpdate_2{
		SignMethod:   signMethod,
		HashVauleLen: len(hash),
		HashVaule:    hash,
		InDataLen:    len(data),
		InData:       data,
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataUpdateRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignDataUpdate,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignDataUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.8 多包数字签名结束
func (b *SVSRequestBuilder) BuildSignDataFinalRequest(signMethod, keyIdx int, keyValue, hash []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("SignDataFinalRequest SignMethod Type Error")
	}

	inner := Request_SignDataFinal_2{
		SignMethod:   signMethod,
		KeyIndex:     keyIdx,
		KeyValue:     keyValue,
		HashVauleLen: len(hash),
		HashVaule:    hash,
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataFinalRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignDataFinal,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignDataFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.9 多包验证数字签名初始化
func (b *SVSRequestBuilder) BuildVerifySignedDataInitRequest(signMethod int, sPubK, sID, data []byte) ([]byte, error) {
	inner := Request_VerifySignedDataInit_2{}
	if signMethod == SGD_SM3_RSA ||
		signMethod == SGD_SM3_SM2 {

		inner.SignerPublicKey = sPubK
		inner.SignerIDLen = len(sID)
		inner.SignerID = sID

	} else if signMethod == SGD_SHA1_RSA ||
		signMethod == SGD_SHA256_RSA {

	} else {
		return nil, fmt.Errorf("VerifySignedDataInitRequest SignMethod Type Error")
	}
	inner.SignMethod = signMethod
	inner.InDataLen = len(data)
	inner.InData = data

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataInitRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedDataInit,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedDataInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.10 多包验证数字签名更新
func (b *SVSRequestBuilder) BuildVerifySignedDataUpdateRequest(signMethod int, hash, data []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("VerifySignedDataUpdateRequest SignMethod Type Error")
	}

	inner := Request_VerifySignedDataUpdate_2{
		SignMethod:   signMethod,
		HashVauleLen: len(hash),
		HashVaule:    hash,
		InDataLen:    len(data),
		InData:       data,
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataUpdateRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedDataUpdate,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedDataUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.11 多包验证数字签名结束
/*
	type 1:cert	2:srial
	level 0:timeOnly	1:time&&sign	2.time&&sign&&CRL
*/
func (b *SVSRequestBuilder) BuildVerifySignedDataFinalRequest(signMethod, typev int, v, hash, sig []byte, vfyLevel int) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("VerifySignedDataFinalRequest SignMethod Type Error")
	}

	if vfyLevel != VefifySignDataRequestType_VfyLevelTime &&
		vfyLevel != VefifySignDataRequestType_VfyLevelSig &&
		vfyLevel != VefifySignDataRequestType_VfyLevelAll {
		return nil, fmt.Errorf("VerifySignedDataFinalRequest VerifyLevel Type Error")
	}

	rawsig, err := Encode_bSM2Sig_2_asn1RawSM2sig(sig, 5)
	if err != nil {
		return nil, err
	}

	inner := Request_VerifySignedDataFinal_2{
		SignMethod:   signMethod,
		Type:         typev,
		HashValueLen: len(hash),
		HashValue:    hash,
		Signature:    rawsig,
		VerifyLevel:  vfyLevel,
	}
	if typev == VefifySignDataRequestType_Cert {
		inner.Cert.Class = asn1.ClassContextSpecific
		inner.Cert.Tag = 0
		inner.Cert.IsCompound = true
		inner.Cert.Bytes = v
	} else if typev == VefifySignDataRequestType_Serial {
		inner.CertSN.Class = asn1.ClassContextSpecific
		inner.CertSN.Tag = 1
		inner.CertSN.IsCompound = true
		inner.CertSN.Bytes = v
	} else {
		return nil, fmt.Errorf("VerifySignedDataFinalRequest Type Error")

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataFinalRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedDataFinal,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedDataFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.12 单包消息签名
func (b *SVSRequestBuilder) BuildSignMessageRequest(signMethod, keyIndex int, keyValue, inData []byte,
	hashFlag, orgText, cerChain, crl, authenAttribute bool) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("SignMessageRequest SignMethod Type Error")
	}

	inner := Request_SignMessage_2{
		SignMethod:               signMethod,
		KeyIndex:                 keyIndex,
		KeyValue:                 keyValue,
		InDataLen:                len(inData),
		InData:                   inData,
		HashFlag:                 hashFlag,
		OriginalText:             orgText,
		CertificateChain:         cerChain,
		Crl:                      crl,
		AuthenticationAttributes: authenAttribute,
	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignMessage,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignMessage],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.13 单包验证消息签名
func (b *SVSRequestBuilder) BuildVerifySignedMessageRequest(inData, signedMessage []byte,
	hashFlag, orgText, cerChain, crl, authenAttribute bool) ([]byte, error) {
	inner := Request_VerifySignedMessage_2{
		InDataLen:                len(inData),
		InData:                   inData,
		SignedMessage:            signedMessage,
		HashFlag:                 hashFlag,
		OriginalText:             orgText,
		CertificateChain:         cerChain,
		Crl:                      crl,
		AuthenticationAttributes: authenAttribute,
	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedMessageRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedMessage,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedMessage],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.14 多包消息签名初始化
func (b *SVSRequestBuilder) BuildSignMessageInitRequest(signMethod int, sPubK, sID, data []byte) ([]byte, error) {
	inner := Request_SignMessageInit_2{}
	if signMethod == SGD_SM3_RSA ||
		signMethod == SGD_SM3_SM2 {

		inner.SignerPublicKey = sPubK
		inner.SignerIDLen = len(sID)
		inner.SignerID = sID

	} else if signMethod == SGD_SHA1_RSA ||
		signMethod == SGD_SHA256_RSA {

	} else {
		return nil, fmt.Errorf("SignMessageInitRequest SignMethod Type Error")
	}
	inner.SignMethod = signMethod
	inner.InDataLen = len(data)
	inner.InData = data

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageInitRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignMessageInit,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignMessageInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.15 多包消息签名更新
func (b *SVSRequestBuilder) BuildSignMessageUpdateRequest(signMethod int, hash, data []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("SignMessageUpdateRequest SignMethod Type Error")
	}

	inner := Request_SignMessageUpdate_2{
		SignMethod:   signMethod,
		HashVauleLen: len(hash),
		HashVaule:    hash,
		InDataLen:    len(data),
		InData:       data,
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageUpdateRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignMessageUpdate,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignMessageUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.16 多包消息签名结束
func (b *SVSRequestBuilder) BuildSignMessageFinalRequest(signMethod, keyIdx int, pivPIN, hash []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("SignMessageFinalRequest SignMethod Type Error")
	}

	inner := Request_SignMessageFinal_2{
		SignMethod:   signMethod,
		KeyIndex:     keyIdx,
		KeyValue:     pivPIN,
		HashVauleLen: len(hash),
		HashVaule:    hash,
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageFinalRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_SignMessageFinal,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_SignMessageFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.17 多包验证消息签名初始化
func (b *SVSRequestBuilder) BuildVerifySignedMessageInitRequest(signMethod int, sPubK, sID, data []byte) ([]byte, error) {
	inner := Request_VerifySignedMessageInit_2{}
	if signMethod == SGD_SM3_RSA ||
		signMethod == SGD_SM3_SM2 {

		inner.SignerPublicKey = sPubK
		inner.SignerIDLen = len(sID)
		inner.SignerID = sID

	} else if signMethod == SGD_SHA1_RSA ||
		signMethod == SGD_SHA256_RSA {

	} else {
		return nil, fmt.Errorf("VerifySignedMessageInitRequest SignMethod Type Error")
	}
	inner.SignMethod = signMethod
	inner.InDataLen = len(data)
	inner.InData = data

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedMessageInitRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedMessageInit,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedMessageInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.18 多包验证消息签名更新
func (b *SVSRequestBuilder) BuildVerifySignedMessageUpdateRequest(signMethod int, hash, data []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("VerifySignedMessageUpdateRequest SignMethod Type Error")
	}

	inner := Request_VerifySignedMessageUpdate_2{
		SignMethod:   signMethod,
		HashVauleLen: len(hash),
		HashVaule:    hash,
		InDataLen:    len(data),
		InData:       data,
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedMessageUpdateRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedMessageUpdate,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedMessageUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}

// 5.19 多包验证消息签名结束
func (b *SVSRequestBuilder) BuildVerifySignedMessageFinalRequest(signMethod int, hash, sigder []byte) ([]byte, error) {
	if signMethod != SGD_SM3_RSA &&
		signMethod != SGD_SHA1_RSA &&
		signMethod != SGD_SHA256_RSA &&
		signMethod != SGD_SM3_SM2 {
		return nil, fmt.Errorf("BuildVerifySignedMessageFinalRequest SignMethod Type Error")
	}

	// rawsig, err := encode_bSM2Sig_2_asn1RawSM2sig(sig, 3)
	// if err != nil {
	// 	return nil, err
	// }

	inner := Request_VerifySignedMessageFinal_2{
		SignMethod:    signMethod,
		HashVauleLen:  len(hash),
		HashVaule:     hash,
		SignedMessage: sigder,
	}
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("BuildVerifySignedMessageFinalRequest Marshal Error[%s]", err)
	}
	req := SvsRequest_1{
		ReqType: ReqType_VerifySignedMessageFinal,
		Request: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        ReqTypeTag[ReqType_VerifySignedMessageFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		ReqTime: time.Now().UTC(),
	}

	return asn1.Marshal(req)
}
