package test

import (
	"encoding/pem"
	"fmt"
	"os"
	a1 "sig_vfy/src/sigvfy/sv0029_asn1"
	"testing"
)

// 1：RespType_ExportCert
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 0
	[0] (671 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (658 byte) SEQUENCE (2 elem)
			[0] (1 elem)
				INTEGER 0
			[1] (1 elem)
				SEQUENCE (3 elem)
	[22] (1 elem)
		UTCTime 2025-04-02 09:40:51 UTC
*/
func TestExportCertResp(t *testing.T) {
	fmt.Println("==================EncodeExportCert==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	crt, _ := os.ReadFile("./ca.crt")
	crtDER, _ := pem.Decode(crt)

	data, err := builder.BuildExportCertRespond(rspvalue, crtDER.Bytes)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeExportCert==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_ExportCert, sttype, false)
		equal_int("rspvalue", a1.RespType_ExportCert, intf.(*a1.Respond_ExportCert_2).RespVaule, true)
		equal_bytes("Cert", crtDER.Bytes, (intf.(*a1.Respond_ExportCert_2).Cert.Bytes), true)
	}
}

// 2：RespType_ParseCert
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 1
	[1] (19 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (8 byte) testInfo
	[22] (1 elem)
		UTCTime 2025-04-02 09:45:03 UTC
*/
func TestParseCertResp(t *testing.T) {
	fmt.Println("==================EncodeParseCert==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	info := []byte("testInfo")
	data, err := builder.BuildParseCertRespond(rspvalue, info)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeParseCert==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_ParseCert, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_ParseCert_2).RespVaule, true)
		equal_bytes("Info", info, intf.(*a1.Respond_ParseCert_2).Info, false)
	}
}

// 3.RespType_ValidateCert
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 2
	[2] (7 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			INTEGER 1
	[22] (1 elem)
		UTCTime 2025-04-02 09:46:31 UTC
*/
func TestValidateCertResp(t *testing.T) {
	fmt.Println("==================EncodeValidateCert==================")
	builder := a1.NewSVSRespondBuilder()

	rspvalue := 0
	state := 1
	data, err := builder.BuildValidateCertRespond(rspvalue, state)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeValidateCert==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_ValidateCert, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_ValidateCert_2).RespVaule, true)
		equal_int("State", state, intf.(*a1.Respond_ValidateCert_2).State, false)
	}
}

// 4.RespType_SignData
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 3
	[3] (79 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			SEQUENCE (2 elem)
				INTEGER (255 bit) 5264753882616949270107378747098155285546805503845970026396009435330698…
				INTEGER (255 bit) 5264753882616949270107378747098155285546805503845970026396009435330698…
	[22] (1 elem)
		UTCTime 2025-04-02 09:50:34 UTC
*/
func TestSignDataResp(t *testing.T) {
	fmt.Println("==================EncodeSignData==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	sig := []byte("testSig1testSig1testSig1testSig1testSig1testSig1testSig1testSig1")

	data, err := builder.BuildSignDataRespond(rspvalue, sig)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignData==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignData, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_SignData_2).RespVaule, true)
		bsig, _ := a1.Decode_asn1RawSM2Sig_2_bSM2Sig(intf.(*a1.Respond_SignData_2).Signature)
		equal_bytes("KeyValue", sig, bsig, false)
	}
}

// 5.RespType_VerifySignedData
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 4
	[4] (7 byte) SEQUENCE (1 elem)
		[0] (1 elem)
			INTEGER 0
	[22] (1 elem)
		UTCTime 2025-04-02 09:51:29 UTC
*/
func TestVerifySignedDataResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedData==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0

	data, err := builder.BuildVerifySignedDataRespond(rspvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedData==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedData, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedData_2).RespVaule, true)
	}
}

// 6.RespType_SignDataInit
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 5
	[5] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 09:52:06 UTC
*/
func TestSignDataInitResp(t *testing.T) {
	fmt.Println("==================EncodeSignDataInit==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildSignDataInitRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignDataInit==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignDataInit, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_SignDataInit_2).RespVaule, true)
		equal_bytes("InData", hashvalue, intf.(*a1.Respond_SignDataInit_2).HashValue, false)
	}
}

// 7.RespType_SignDataUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 6
	[6] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 09:52:59 UTC
*/
func TestSignDataUpdateResp(t *testing.T) {
	fmt.Println("==================EncodeSignDataUpdate==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildSignDataUpdateRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignDataUpdate==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignDataUpdate, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_SignDataUpdate_2).RespVaule, true)
		equal_bytes("InData", hashvalue, intf.(*a1.Respond_SignDataUpdate_2).HashValue, false)
	}
}

// 8.RespType_SignDataFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 7
	[7] (79 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			SEQUENCE (2 elem)
				INTEGER (255 bit) 5264753882616949270735088920636823361964412682858830514354427114927649…
				INTEGER (255 bit) 5264753882616949270735088920636823361964412682858830514354427114927649…
	[22] (1 elem)
		UTCTime 2025-04-02 09:53:53 UTC
*/
func TestSignDataFinalResp(t *testing.T) {
	fmt.Println("==================EncodeSignDataFinal==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	sig := []byte("testSig2testSig2testSig2testSig2testSig2testSig2testSig2testSig2")

	data, err := builder.BuildSignDataFinalRespond(rspvalue, sig)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignDataFinal==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignDataFinal, sttype, false)
		equal_int("SignMethod", rspvalue, intf.(*a1.Respond_SignDataFinal_2).RespVaule, true)
		bsig, _ := a1.Decode_asn1RawSM2Sig_2_bSM2Sig(intf.(*a1.Respond_SignDataFinal_2).Signature)
		equal_bytes("HashVaule", sig, bsig, false)
	}
}

// 9.RespType_VerifySignedDataInit
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 8
	[8] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 09:54:42 UTC
*/
func TestVerifySignedDataInitResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedDataInit==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildVerifySignedDataInitRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedDataInit==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedDataInit, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedDataInit_2).RespVaule, true)
		equal_bytes("HashValue", hashvalue, intf.(*a1.Respond_VerifySignedDataInit_2).HashValue, false)
	}
}

// 10.RespType_VerifySignedDataUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 9
	[9] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 09:55:25 UTC
*/
func TestVerifySignedDataUpdateResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedDataUpdate==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildVerifySignedDataUpdateRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedDataUpdate==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedDataUpdate, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedDataUpdate_2).RespVaule, true)
		equal_bytes("HashValue", hashvalue, intf.(*a1.Respond_VerifySignedDataUpdate_2).HashValue, false)
	}
}

// 11.RespType_VerifySignedDataFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 10
	[10] (7 byte) SEQUENCE (1 elem)
		[0] (1 elem)
			INTEGER 0
	[22] (1 elem)
		UTCTime 2025-04-02 09:56:03 UTC
*/
func TestVerifySignedDataFinalResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedDataFinal==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0

	data, err := builder.BuildVerifySignedDataFinalRespond(rspvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedDataFinal==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedDataFinal, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedDataFinal_2).RespVaule, true)
	}
}

// 12.RespType_SignMessage
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 11
	[11] (28 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (17 byte) testSignedMessage
	[22] (1 elem)
		UTCTime 2025-04-02 09:56:41 UTC
*/
func TestSignMessageResp(t *testing.T) {
	fmt.Println("==================EncodeSignMessage==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	signedmsg := []byte("testSignedMessage")

	data, err := builder.BuildSignMessageRespond(rspvalue, signedmsg)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessage==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignMessage, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_SignMessage_2).RespVaule, true)
		equal_bytes("SignedMessage", signedmsg, intf.(*a1.Respond_SignMessage_2).SignedMessage, false)
	}
}

// 13.RespType_VerifySignedMessage
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 12
	[12] (7 byte) SEQUENCE (1 elem)
		[0] (1 elem)
			INTEGER 0
	[22] (1 elem)
		UTCTime 2025-04-02 09:57:26 UTC
*/
func TestVerifySignedMessageResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessage==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0

	data, err := builder.BuildVerifySignedMessageRespond(rspvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessage==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedMessage, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedMessage_2).RespVaule, true)
	}
}

// 14.RespType_SignMessageInit
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 13
	[13] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 09:58:03 UTC
*/
func TestSignMessageInitResp(t *testing.T) {
	fmt.Println("==================EncodeSignMessageInit==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildSignMessageInitRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessageInit==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignMessageInit, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_SignMessageInit_2).RespVaule, true)
		equal_bytes("HashValue", hashvalue, intf.(*a1.Respond_SignMessageInit_2).HashValue, false)
	}
}

// 15.RespType_SignMessageUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 14
	[14] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 09:58:46 UTC
*/
func TestSignMessageUpdateResp(t *testing.T) {
	fmt.Println("==================EncodeSignMessageUpdate==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildSignMessageUpdateRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessageUpdate==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignMessageUpdate, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_SignMessageUpdate_2).RespVaule, true)
		equal_bytes("HashValue", hashvalue, intf.(*a1.Respond_SignMessageUpdate_2).HashValue, false)
	}
}

// 16.RespType_SignMessageFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 15
	[15] (28 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (17 byte) testSignedMessage
	[22] (1 elem)
		UTCTime 2025-04-02 09:59:21 UTC
*/
func TestSignMessageFinalResp(t *testing.T) {
	fmt.Println("==================EncodeSignMessageFinal==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	signedmsg := []byte("testSignedMessage")

	data, err := builder.BuildSignMessageFinalRespond(rspvalue, signedmsg)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessageFinal==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_SignMessageFinal, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_SignMessageFinal_2).RespVaule, true)
		equal_bytes("SignedMessage", signedmsg, intf.(*a1.Respond_SignMessageFinal_2).SignedMessage, false)
	}
}

// 17.RespType_VerifySignedMessageInit
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 16
	[16] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 10:00:09 UTC
*/
func TestVerifySignedMessageInitResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessageInit==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildVerifySignedMessageInitRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessageInit==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedMessageInit, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedMessageInit_2).RespVaule, true)
		equal_bytes("HashValue", hashvalue, intf.(*a1.Respond_VerifySignedMessageInit_2).HashValue, false)
	}
}

// 18.RespType_VerifySignedMessageUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 17
	[17] (43 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 0
		[1] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 10:00:49 UTC
*/
func TestVerifySignedMessageUpdateResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessageUpdate==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0
	hashvalue := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildVerifySignedMessageUpdateRespond(rspvalue, hashvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessageUpdate==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedMessageUpdate, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedMessageUpdate_2).RespVaule, true)
		equal_bytes("HashValue", hashvalue, intf.(*a1.Respond_VerifySignedMessageUpdate_2).HashValue, false)
	}
}

// 19.RespType_VerifySignedMessageFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 18
	[18] (7 byte) SEQUENCE (1 elem)
		[0] (1 elem)
			INTEGER 0
	[22] (1 elem)
		UTCTime 2025-04-02 10:01:26 UTC
*/
func TestVerifySignedMessageFinalResp(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessageFinal==================")
	builder := a1.NewSVSRespondBuilder()
	rspvalue := 0

	data, err := builder.BuildVerifySignedMessageFinalRespond(rspvalue)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessageFinal==================")
	sttype, intf, err := a1.ParseRespond(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.RespType_VerifySignedMessageFinal, sttype, false)
		equal_int("RespVaule", rspvalue, intf.(*a1.Respond_VerifySignedMessageFinal_2).RespVaule, true)
	}
}
