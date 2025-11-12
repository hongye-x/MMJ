package sv0029_asn1

import (
	"encoding/asn1"
	"fmt"
)

// 解析主请求结构
func parseSVSRequest(data []byte) (*SvsRequest_1, error) {
	var req SvsRequest_1
	// 使用UnmarshalWithParams并指定参数
	_, err := asn1.Unmarshal(data, &req)
	if err != nil {
		return nil, fmt.Errorf("Parse Request Error[%s]", err)
	}
	return &req, nil
}

// 解析导出证书请求
func parseExportCertRequest(innerDER []byte) (*Request_ExportCert_2, error) {
	var inner Request_ExportCert_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析证书解析请求
func parseParseCertRequest(innerDER []byte) (*Request_ParseCert_2, error) {
	var inner Request_ParseCert_2
	_, err := asn1.UnmarshalWithParams(innerDER, &inner, "")
	return &inner, err
}

// 解析证书验证请求
func parseValidateCertRequest(innerDER []byte) (*Request_ValidateCert_2, error) {
	var inner Request_ValidateCert_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包签名请求
func parseSignDataRequest(innerDER []byte) (*Request_SignData_2, error) {
	var inner Request_SignData_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包验证签名请求
func parseVerifySignedDataRequest(innerDER []byte) (*Request_VerifySignedData_2, error) {
	var inner Request_VerifySignedData_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包签名初始化请求
func parseSignDataInitRequest(innerDER []byte) (*Request_SignDataInit_2, error) {
	var inner Request_SignDataInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包签名更新请求
func parseSignDataUpdateRequest(innerDER []byte) (*Request_SignDataUpdate_2, error) {
	var inner Request_SignDataUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包签名结束请求
func parseSignDataFinalRequest(innerDER []byte) (*Request_SignDataFinal_2, error) {
	var inner Request_SignDataFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包验证初始化请求
func parseVerifySignedDataInitRequest(innerDER []byte) (*Request_VerifySignedDataInit_2, error) {
	var inner Request_VerifySignedDataInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包验证更新请求
func parseVerifySignedDataUpdateRequest(innerDER []byte) (*Request_VerifySignedDataUpdate_2, error) {
	var inner Request_VerifySignedDataUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包验证结束请求
func parseVerifySignedDataFinalRequest(innerDER []byte) (*Request_VerifySignedDataFinal_2, error) {
	var inner Request_VerifySignedDataFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包消息签名请求
func parseSignMessageRequest(innerDER []byte) (*Request_SignMessage_2, error) {
	var inner Request_SignMessage_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析单包消息验证请求
func parseVerifySignedMessageRequest(innerDER []byte) (*Request_VerifySignedMessage_2, error) {
	var inner Request_VerifySignedMessage_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息签名初始化请求
func parseSignMessageInitRequest(innerDER []byte) (*Request_SignMessageInit_2, error) {
	var inner Request_SignMessageInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息签名更新请求
func parseSignMessageUpdateRequest(innerDER []byte) (*Request_SignMessageUpdate_2, error) {
	var inner Request_SignMessageUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息签名结束请求
func parseSignMessageFinalRequest(innerDER []byte) (*Request_SignMessageFinal_2, error) {
	var inner Request_SignMessageFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息验证初始化请求
func parseVerifySignedMessageInitRequest(innerDER []byte) (*Request_VerifySignedMessageInit_2, error) {
	var inner Request_VerifySignedMessageInit_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息验证更新请求
func parseVerifySignedMessageUpdateRequest(innerDER []byte) (*Request_VerifySignedMessageUpdate_2, error) {
	var inner Request_VerifySignedMessageUpdate_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

// 解析多包消息验证结束请求
func parseVerifySignedMessageFinalRequest(innerDER []byte) (*Request_VerifySignedMessageFinal_2, error) {
	var inner Request_VerifySignedMessageFinal_2
	_, err := asn1.Unmarshal(innerDER, &inner)
	return &inner, err
}

func ParseRequest(data []byte) (int, interface{}, error) {
	req, err := parseSVSRequest(data)
	if err != nil {
		return 0, nil, err
	}
	innerDER := req.Request.Bytes
	var st interface{}
	switch req.ReqType {
	case ReqType_ExportCert:
		st, err = parseExportCertRequest(innerDER)
	case ReqType_ParseCert:
		st, err = parseParseCertRequest(innerDER)
	case ReqType_ValidateCert:
		st, err = parseValidateCertRequest(innerDER)
	case ReqType_SignData:
		st, err = parseSignDataRequest(innerDER)
	case ReqType_VerifySignedData:
		st, err = parseVerifySignedDataRequest(innerDER)
	case ReqType_SignDataInit:
		st, err = parseSignDataInitRequest(innerDER)
	case ReqType_SignDataUpdate:
		st, err = parseSignDataUpdateRequest(innerDER)
	case ReqType_SignDataFinal:
		st, err = parseSignDataFinalRequest(innerDER)
	case ReqType_VerifySignedDataInit:
		st, err = parseVerifySignedDataInitRequest(innerDER)
	case ReqType_VerifySignedDataUpdate:
		st, err = parseVerifySignedDataUpdateRequest(innerDER)
	case ReqType_VerifySignedDataFinal:
		st, err = parseVerifySignedDataFinalRequest(innerDER)
	case ReqType_SignMessage:
		st, err = parseSignMessageRequest(innerDER)
	case ReqType_VerifySignedMessage:
		st, err = parseVerifySignedMessageRequest(innerDER)
	case ReqType_SignMessageInit:
		st, err = parseSignMessageInitRequest(innerDER)
	case ReqType_SignMessageUpdate:
		st, err = parseSignMessageUpdateRequest(innerDER)
	case ReqType_SignMessageFinal:
		st, err = parseSignMessageFinalRequest(innerDER)
	case ReqType_VerifySignedMessageInit:
		st, err = parseVerifySignedMessageInitRequest(innerDER)
	case ReqType_VerifySignedMessageUpdate:
		st, err = parseVerifySignedMessageUpdateRequest(innerDER)
	case ReqType_VerifySignedMessageFinal:
		st, err = parseVerifySignedMessageFinalRequest(innerDER)
	default:
		return 0, nil, fmt.Errorf("Unknow Requset Type[%08X]", req.ReqType)
	}
	return req.ReqType, st, err
}
