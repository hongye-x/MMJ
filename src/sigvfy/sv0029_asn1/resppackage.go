package sv0029_asn1

import (
	"encoding/asn1"
	"fmt"
	"time"
)

type SVSRespondBuilder struct {
	Version int
}

func NewSVSRespondBuilder() *SVSRespondBuilder {
	return &SVSRespondBuilder{
		Version: VersionDefault,
	}
}

// 5.1 导出证书
func (b *SVSRespondBuilder) BuildExportCertRespond(respvalue int, cert []byte) ([]byte, error) {
	inner := Respond_ExportCert_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.Cert.Class = asn1.ClassContextSpecific
		inner.Cert.Tag = 1
		inner.Cert.IsCompound = true
		inner.Cert.Bytes = cert
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("ExportCertRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_ExportCert,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_ExportCert],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.2 解析证书
func (b *SVSRespondBuilder) BuildParseCertRespond(respvalue int, info []byte) ([]byte, error) {
	inner := Respond_ParseCert_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.Info = info
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("ParseCertRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_ParseCert,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_ParseCert],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.3 解析证书
func (b *SVSRespondBuilder) BuildValidateCertRespond(respvalue, state int) ([]byte, error) {
	inner := Respond_ValidateCert_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.State = state
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("ValidateCertRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_ValidateCert,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_ValidateCert],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.4 单包数字签名
func (b *SVSRespondBuilder) BuildSignDataRespond(respvalue int, sig []byte) ([]byte, error) {
	inner := Respond_SignData_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		rawsig, err := Encode_bSM2Sig_2_asn1RawSM2sig(sig, 1)
		if err != nil {
			return nil, fmt.Errorf("VerifySignedDataRequest %s", err)
		}
		inner.Signature = rawsig
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignData,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignData],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.5 单包验证数字签名
func (b *SVSRespondBuilder) BuildVerifySignedDataRespond(respvalue int) ([]byte, error) {
	inner := Respond_VerifySignedData_2{}
	inner.RespVaule = respvalue

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedData,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedData],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.6 多包数字签名初始化
func (b *SVSRespondBuilder) BuildSignDataInitRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_SignDataInit_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataInitRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignDataInit,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignDataInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.7 多包数字签名更新
func (b *SVSRespondBuilder) BuildSignDataUpdateRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_SignDataUpdate_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataUpdateRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignDataUpdate,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignDataUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.8 多包数字签名更新
func (b *SVSRespondBuilder) BuildSignDataFinalRespond(respvalue int, sig []byte) ([]byte, error) {
	inner := Respond_SignDataFinal_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		rawsig, err := Encode_bSM2Sig_2_asn1RawSM2sig(sig, 1)
		if err != nil {
			return nil, fmt.Errorf("BuildSignDataFinalRespond %s", err)
		}
		inner.Signature = rawsig
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignDataFinalRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignDataFinal,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignDataFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.9 多包验证数字签名初始化
func (b *SVSRespondBuilder) BuildVerifySignedDataInitRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_VerifySignedDataInit_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataInitRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedDataInit,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedDataInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.10 多包验证数字签名更新
func (b *SVSRespondBuilder) BuildVerifySignedDataUpdateRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_VerifySignedDataUpdate_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataUpdateRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedDataUpdate,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedDataUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.11 多包验证数字签名结束
func (b *SVSRespondBuilder) BuildVerifySignedDataFinalRespond(respvalue int) ([]byte, error) {
	inner := Respond_VerifySignedDataFinal_2{}
	inner.RespVaule = respvalue

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedDataFinalRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedDataFinal,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedDataFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.12 单包消息签名
func (b *SVSRespondBuilder) BuildSignMessageRespond(respvalue int, signedmessage []byte) ([]byte, error) {
	inner := Respond_SignMessage_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.SignedMessage = signedmessage
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignMessage,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignMessage],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.13 单包验证消息签名
func (b *SVSRespondBuilder) BuildVerifySignedMessageRespond(respvalue int) ([]byte, error) {
	inner := Respond_VerifySignedMessage_2{}
	inner.RespVaule = respvalue

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedMessageRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedMessage,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedMessage],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.14 多包消息签名初始化
func (b *SVSRespondBuilder) BuildSignMessageInitRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_SignMessageInit_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageInitRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignMessageInit,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignMessageInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.15 多包消息签名更新
func (b *SVSRespondBuilder) BuildSignMessageUpdateRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_SignMessageUpdate_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageUpdateRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignMessageUpdate,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignMessageUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.16 多包消息签名结束
func (b *SVSRespondBuilder) BuildSignMessageFinalRespond(respvalue int, signedmessage []byte) ([]byte, error) {
	inner := Respond_SignMessageFinal_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.SignedMessage = signedmessage
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("SignMessageFinalRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_SignMessageFinal,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_SignMessageFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.17 多包验证消息签名初始化
func (b *SVSRespondBuilder) BuildVerifySignedMessageInitRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_VerifySignedMessageInit_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedMessageInitRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedMessageInit,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedMessageInit],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.18 多包验证消息签名更新
func (b *SVSRespondBuilder) BuildVerifySignedMessageUpdateRespond(respvalue int, hashvalue []byte) ([]byte, error) {
	inner := Respond_VerifySignedMessageUpdate_2{}
	inner.RespVaule = respvalue
	if respvalue == 0 {
		inner.HashValue = hashvalue
	} else {

	}

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedMessageUpdateRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedMessageUpdate,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedMessageUpdate],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}

// 5.19 多包验证消息签名结束
func (b *SVSRespondBuilder) BuildVerifySignedMessageFinalRespond(respvalue int) ([]byte, error) {
	inner := Respond_VerifySignedMessageFinal_2{}
	inner.RespVaule = respvalue

	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("VerifySignedMessageFinalRespond Marshal Error[%s]", err)
	}
	resp := SVSRespond_1{
		RespType: RespType_VerifySignedMessageFinal,
		Respond: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        RespTypeTag[RespType_VerifySignedMessageFinal],
			IsCompound: false,
			Bytes:      innerDER,
		},
		RespTime: time.Now().UTC(),
	}
	return asn1.Marshal(resp)
}
