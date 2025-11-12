package sv0029_asn1

import (
	"encoding/asn1"
	"fmt"
)

// 解析主请求结构
func parseSVSRespond(data []byte) (*SVSRespond_1, error) {
	var req SVSRespond_1
	// 使用UnmarshalWithParams并指定参数
	_, err := asn1.Unmarshal(data, &req)
	if err != nil {
		return nil, fmt.Errorf("Parse Respond Error[%s]", err)
	}
	return &req, nil
}

// 解析导出证书请求
func parseExportCertRespond(innerDER []byte) (*Respond_ExportCert_2, error) {
	var inner Respond_ExportCert_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析证书解析请求
func parseParseCertRespond(innerDER []byte) (*Respond_ParseCert_2, error) {
	var inner Respond_ParseCert_2
	_, err := asn1.UnmarshalWithParams(innerDER, &inner, "")
	return &inner, err
}

// 解析证书验证请求
func parseValidateCertRespond(innerDER []byte) (*Respond_ValidateCert_2, error) {
	var inner Respond_ValidateCert_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包签名请求
func parseSignDataRespond(innerDER []byte) (*Respond_SignData_2, error) {
	var inner Respond_SignData_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包验证签名请求
func parseVerifySignedDataRespond(innerDER []byte) (*Respond_VerifySignedData_2, error) {
	var inner Respond_VerifySignedData_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包签名初始化请求
func parseSignDataInitRespond(innerDER []byte) (*Respond_SignDataInit_2, error) {
	var inner Respond_SignDataInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包签名更新请求
func parseSignDataUpdateRespond(innerDER []byte) (*Respond_SignDataUpdate_2, error) {
	var inner Respond_SignDataUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包签名结束请求
func parseSignDataFinalRespond(innerDER []byte) (*Respond_SignDataFinal_2, error) {
	var inner Respond_SignDataFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包验证初始化请求
func parseVerifySignedDataInitRespond(innerDER []byte) (*Respond_VerifySignedDataInit_2, error) {
	var inner Respond_VerifySignedDataInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包验证更新请求
func parseVerifySignedDataUpdateRespond(innerDER []byte) (*Respond_VerifySignedDataUpdate_2, error) {
	var inner Respond_VerifySignedDataUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包验证结束请求
func parseVerifySignedDataFinalRespond(innerDER []byte) (*Respond_VerifySignedDataFinal_2, error) {
	var inner Respond_VerifySignedDataFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包消息签名请求
func parseSignMessageRespond(innerDER []byte) (*Respond_SignMessage_2, error) {
	var inner Respond_SignMessage_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包消息验证请求
func parseVerifySignedMessageRespond(innerDER []byte) (*Respond_VerifySignedMessage_2, error) {
	var inner Respond_VerifySignedMessage_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息签名初始化请求
func parseSignMessageInitRespond(innerDER []byte) (*Respond_SignMessageInit_2, error) {
	var inner Respond_SignMessageInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息签名更新请求
func parseSignMessageUpdateRespond(innerDER []byte) (*Respond_SignMessageUpdate_2, error) {
	var inner Respond_SignMessageUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息签名结束请求
func parseSignMessageFinalRespond(innerDER []byte) (*Respond_SignMessageFinal_2, error) {
	var inner Respond_SignMessageFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息验证初始化请求
func parseVerifySignedMessageInitRespond(innerDER []byte) (*Respond_VerifySignedMessageInit_2, error) {
	var inner Respond_VerifySignedMessageInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息验证更新请求
func parseVerifySignedMessageUpdateRespond(innerDER []byte) (*Respond_VerifySignedMessageUpdate_2, error) {
	var inner Respond_VerifySignedMessageUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息验证结束请求
func parseVerifySignedMessageFinalRespond(innerDER []byte) (*Respond_VerifySignedMessageFinal_2, error) {
	var inner Respond_VerifySignedMessageFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

func ParseRespond(data []byte) (int, interface{}, error) {
	req, err := parseSVSRespond(data)
	if err != nil {
		return 0, nil, err
	}
	innerDER := req.Respond.Bytes
	var st interface{}
	switch req.RespType {
	case ReqType_ExportCert:
		st, err = parseExportCertRespond(innerDER)
	case ReqType_ParseCert:
		st, err = parseParseCertRespond(innerDER)
	case ReqType_ValidateCert:
		st, err = parseValidateCertRespond(innerDER)
	case ReqType_SignData:
		st, err = parseSignDataRespond(innerDER)
	case ReqType_VerifySignedData:
		st, err = parseVerifySignedDataRespond(innerDER)
	case ReqType_SignDataInit:
		st, err = parseSignDataInitRespond(innerDER)
	case ReqType_SignDataUpdate:
		st, err = parseSignDataUpdateRespond(innerDER)
	case ReqType_SignDataFinal:
		st, err = parseSignDataFinalRespond(innerDER)
	case ReqType_VerifySignedDataInit:
		st, err = parseVerifySignedDataInitRespond(innerDER)
	case ReqType_VerifySignedDataUpdate:
		st, err = parseVerifySignedDataUpdateRespond(innerDER)
	case ReqType_VerifySignedDataFinal:
		st, err = parseVerifySignedDataFinalRespond(innerDER)
	case ReqType_SignMessage:
		st, err = parseSignMessageRespond(innerDER)
	case ReqType_VerifySignedMessage:
		st, err = parseVerifySignedMessageRespond(innerDER)
	case ReqType_SignMessageInit:
		st, err = parseSignMessageInitRespond(innerDER)
	case ReqType_SignMessageUpdate:
		st, err = parseSignMessageUpdateRespond(innerDER)
	case ReqType_SignMessageFinal:
		st, err = parseSignMessageFinalRespond(innerDER)
	case ReqType_VerifySignedMessageInit:
		st, err = parseVerifySignedMessageInitRespond(innerDER)
	case ReqType_VerifySignedMessageUpdate:
		st, err = parseVerifySignedMessageUpdateRespond(innerDER)
	case ReqType_VerifySignedMessageFinal:
		st, err = parseVerifySignedMessageFinalRespond(innerDER)
	default:
		return 0, nil, fmt.Errorf("Unknow Requset Type[%08X]", req.RespType)
	}
	return req.RespType, st, err
}
