package test

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	a1 "sig_vfy/src/sigvfy/sv0029_asn1"
	"testing"
)

func equal_int(discrib string, org, dst int, hex bool) {
	if hex {
		if org != dst {
			fmt.Printf("\033[31morg %s : %08X\ndst %s : %08X\033[0m\n", discrib, org, discrib, dst)
		} else {
			fmt.Printf("\033[32m%s : %08X\033[0m\n", discrib, dst)
		}
	} else {
		if org != dst {
			fmt.Printf("org %s : %d\ndst %s : %d\033[0m\n", discrib, org, discrib, dst)
		} else {
			fmt.Printf("\033[32m%s : %d\033[0m\n", discrib, dst)
		}
	}
}

func equal_bytes(discrib string, org, dst []byte, hex bool) {
	if hex {
		if !bytes.Equal(org, dst) {
			fmt.Printf("\033[31morg %s : %X\ndst %s : %X\033[0m\n", discrib, org, discrib, dst)
		} else {
			fmt.Printf("\033[32m%s : %X\033[0m\n", discrib, dst)
		}
	} else {
		if !bytes.Equal(org, dst) {
			fmt.Printf("\033[31morg %s : %s\ndst %s : %s\033[0m\n", discrib, org, discrib, dst)
		} else {
			fmt.Printf("\033[32m%s : %s\033[0m\n", discrib, dst)
		}
	}
}

func equal_bool(discrib string, org, dst bool) {
	if org != dst {
		fmt.Printf("\033[31morg %s : %v\ndst %s : %v\033[0m\n", discrib, org, discrib, dst)
	} else {
		fmt.Printf("\033[32m%s : %v\033[0m\n", discrib, dst)
	}
}

// 1：ReqType_ExportCert
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 0
	[0] (9 byte) SEQUENCE (1 elem)
		[0] (1 elem)
			OCTET STRING (3 byte) abc
	[22] (1 elem)
		UTCTime 2025-04-02 06:17:01 UTC
*/
func TestExportCertReq(t *testing.T) {
	fmt.Println("==================EncodeExportCert==================")
	builder := a1.NewSVSRequestBuilder()
	idf := []byte("abc")

	data, err := builder.BuildExportCertRequest(idf)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeExportCert==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_ExportCert, sttype, false)
		equal_bytes("Identification", idf, (intf.(*a1.Request_ExportCert_2).Identification), false)
	}
}

// 2：ReqType_ParseCert
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 1
	[1] (671 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			INTEGER 1
		[1] (1 elem)
			SEQUENCE (3 elem)
	[22] (1 elem)
		UTCTime 2025-04-02 06:18:11 UTC
*/
func TestParseCertReq(t *testing.T) {
	fmt.Println("==================EncodeParseCert==================")
	builder := a1.NewSVSRequestBuilder()

	crt, _ := os.ReadFile("./ca.crt")
	crtDER, _ := pem.Decode(crt)
	InfoType := a1.SGD_CERT_VERSION
	data, err := builder.BuildParseCertRequest(InfoType, crtDER.Bytes)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeParseCert==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_ParseCert, sttype, false)
		equal_int("InfoType", InfoType, intf.(*a1.Request_ParseCert_2).InfoType, false)
		equal_bytes("Cert", crtDER.Bytes, intf.(*a1.Request_ParseCert_2).Cert.Bytes, true)
	}
}

// 3.ReqType_ValidateCert
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 2
	[2] (671 byte) SEQUENCE (2 elem)
		[0] (1 elem)
			SEQUENCE (3 elem)
		[1] (1 elem)
			BOOLEAN true
	[22] (1 elem)
		UTCTime 2025-04-02 06:23:10 UTC
*/
func TestValidateCertReq(t *testing.T) {
	fmt.Println("==================EncodeValidateCert==================")
	builder := a1.NewSVSRequestBuilder()

	crt, _ := os.ReadFile("./ca.crt")
	crtDER, _ := pem.Decode(crt)
	ocsptype := true
	data, err := builder.BuildValidateCertRequest(crtDER.Bytes, ocsptype)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeValidateCert==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_ValidateCert, sttype, false)
		equal_bool("OCSP", ocsptype, intf.(*a1.Request_ValidateCert_2).OCSP)
		equal_bytes("Cert", crtDER.Bytes, intf.(*a1.Request_ValidateCert_2).Cert.Bytes, true)
	}
}

// 4.ReqType_SignData
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 3
	[3] (44 byte) SEQUENCE (5 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 34
		[2] (1 elem)
			OCTET STRING (7 byte) testPIN
		[3] (1 elem)
			INTEGER 10
		[4] (1 elem)
			OCTET STRING (10 byte) testINData
	[22] (1 elem)
		UTCTime 2025-04-02 06:24:19 UTC
*/
func TestSignDataReq(t *testing.T) {
	fmt.Println("==================EncodeSignData==================")
	builder := a1.NewSVSRequestBuilder()
	signmethod := a1.SGD_SM3_SM2
	keyidx := 34
	keyvalue := []byte("testPIN")
	indata := []byte("testINData")

	data, err := builder.BuildSignDataRequest(signmethod, keyidx, keyvalue, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignData==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignData, sttype, false)
		equal_int("SignMethod", signmethod, intf.(*a1.Request_SignData_2).SignMethod, true)
		equal_int("KeyIndex", keyidx, intf.(*a1.Request_SignData_2).KeyIndex, false)
		equal_bytes("KeyValue", keyvalue, intf.(*a1.Request_SignData_2).KeyValue, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_SignData_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_SignData_2).InData, false)
	}
}

// 5.ReqType_VerifySignedData
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 4
	[4] (765 byte) SEQUENCE (6 elem)
		[2] (1 elem)
			INTEGER 1
		[0] (1 elem)
			SEQUENCE (3 elem)
		[3] (1 elem)
			INTEGER 8
		[4] (1 elem)
			OCTET STRING (8 byte) testData
		[5] (1 elem)
			SEQUENCE (2 elem)
				INTEGER (255 bit) 5264753882616949270107378747098155285546805503845970026396009435330698…
				INTEGER (255 bit) 5264753882616949270107378747098155285546805503845970026396009435330698…
		[6] (1 elem)
			INTEGER 2
	[22] (1 elem)
		UTCTime 2025-04-02 06:33:02 UTC
*/
func TestVerifySignedDataReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedData==================")
	builder := a1.NewSVSRequestBuilder()
	atype := 1
	var v []byte
	var p *pem.Block
	if atype == 1 {
		crt, _ := os.ReadFile("./ca.crt")
		p, _ = pem.Decode(crt)
		v = p.Bytes
	} else {
		v = []byte("testSerial")
	}
	indata := []byte("testData")
	sig := []byte("testSig1testSig1testSig1testSig1testSig1testSig1testSig1testSig1")
	vfylevel := 2

	data, err := builder.BuildVerifySignedDataRequest(atype, v, indata, sig, vfylevel)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedData==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedData, sttype, false)
		equal_int("Type", atype, intf.(*a1.Request_VerifySignedData_2).Type, false)
		if atype == 1 {
			equal_bytes("Cert", v, intf.(*a1.Request_VerifySignedData_2).Cert.Bytes, true)
		} else {
			equal_bytes("CertSN", v, intf.(*a1.Request_VerifySignedData_2).CertSN.Bytes, false)
		}
		equal_bytes("InData", indata, intf.(*a1.Request_VerifySignedData_2).InData, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_VerifySignedData_2).InDataLen, false)
		sigbytes, _ := a1.Decode_asn1RawSM2Sig_2_bSM2Sig(intf.(*a1.Request_VerifySignedData_2).Signature)
		equal_bytes("Signature", sig, sigbytes, false)
		equal_int("VerifyLevel", vfylevel, intf.(*a1.Request_VerifySignedData_2).VerifyLevel, false)
	}
}

// 6.ReqType_SignDataInit
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 5
	[5] (49 byte) SEQUENCE (6 elem)
		[3] (1 elem)
			INTEGER 131585
		[0] (10 byte) testPubKey
		[1] (1 byte) 06
		[2] (6 byte) testID
		[4] (1 elem)
			INTEGER 8
		[5] (1 elem)
			OCTET STRING (8 byte) testdata
	[22] (1 elem)
		UTCTime 2025-04-02 06:36:39 UTC
*/
func TestSignDataInitReq(t *testing.T) {
	fmt.Println("==================EncodeSignDataInit==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	sPubK := []byte("testPubKey")
	sID := []byte("testID")
	indata := []byte("testdata")

	data, err := builder.BuildSignDataInitRequest(sigmthod, sPubK, sID, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignDataInit==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignDataInit, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_SignDataInit_2).SignMethod, true)
		if intf.(*a1.Request_SignDataInit_2).SignMethod == a1.SGD_SM3_SM2 ||
			intf.(*a1.Request_SignDataInit_2).SignMethod == a1.SGD_SM3_RSA {
			equal_bytes("SignerPublicKey", sPubK, intf.(*a1.Request_SignDataInit_2).SignerPublicKey, false)
			equal_int("SignerIDLen", len(sID), intf.(*a1.Request_SignDataInit_2).SignerIDLen, true)
			equal_bytes("SignerID", sID, intf.(*a1.Request_SignDataInit_2).SignerID, false)
		}
		equal_int("InDataLen", len(indata), intf.(*a1.Request_SignDataInit_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_SignDataInit_2).InData, false)
	}
}

// 7.ReqType_SignDataUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 6
	[6] (67 byte) SEQUENCE (5 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 32
		[2] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
		[3] (1 elem)
			INTEGER 8
		[4] (1 elem)
			OCTET STRING (8 byte) testData
	[22] (1 elem)
		UTCTime 2025-04-02 06:37:58 UTC
*/
func TestSignDataUpdateReq(t *testing.T) {
	fmt.Println("==================EncodeSignDataUpdate==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	midhash := []byte("testHashtestHashtestHashtestHash")
	indata := []byte("testData")

	data, err := builder.BuildSignDataUpdateRequest(sigmthod, midhash, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignDataUpdate==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignDataUpdate, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_SignDataUpdate_2).SignMethod, true)
		equal_int("HashVauleLen", len(midhash), intf.(*a1.Request_SignDataUpdate_2).HashVauleLen, false)
		equal_bytes("HashVaule", midhash, intf.(*a1.Request_SignDataUpdate_2).HashVaule, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_SignDataUpdate_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_SignDataUpdate_2).InData, false)
	}
}

// 8.ReqType_SignDataFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 7
	[7] (71 byte) SEQUENCE (5 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 126
		[2] (1 elem)
			OCTET STRING (12 byte) testKeyValue
		[3] (1 elem)
			INTEGER 32
		[4] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 06:38:51 UTC
*/
func TestSignDataFinalReq(t *testing.T) {
	fmt.Println("==================EncodeSignDataFinal==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	keyidx := 126
	keyValue := []byte("testKeyValue")
	midhash := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildSignDataFinalRequest(sigmthod, keyidx, keyValue, midhash)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignDataFinal==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignDataFinal, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_SignDataFinal_2).SignMethod, true)
		equal_int("KeyIndex", keyidx, intf.(*a1.Request_SignDataFinal_2).KeyIndex, false)
		equal_bytes("KeyValue", keyValue, intf.(*a1.Request_SignDataFinal_2).KeyValue, false)
		equal_int("HashVauleLen", len(midhash), intf.(*a1.Request_SignDataFinal_2).HashVauleLen, false)
		equal_bytes("HashVaule", midhash, intf.(*a1.Request_SignDataFinal_2).HashVaule, false)
	}
}

// 9.ReqType_VerifySignedDataInit
/*
	SEQUENCE (4 elem)
		[20] (1 elem)
	INTEGER 0
		[21] (1 elem)
	INTEGER 8
	[8] (49 byte) SEQUENCE (6 elem)
		[3] (1 elem)
			INTEGER 131585
		[0] (10 byte) testPubKey
		[1] (1 byte) 06
		[2] (6 byte) testID
		[4] (1 elem)
			INTEGER 8
		[5] (1 elem)
			OCTET STRING (8 byte) testdata
	[22] (1 elem)
		UTCTime 2025-04-02 06:39:45 UTC
*/
func TestVerifySignedDataInitReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedDataInit==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	sPubK := []byte("testPubKey")
	sID := []byte("testID")
	indata := []byte("testdata")

	data, err := builder.BuildVerifySignedDataInitRequest(sigmthod, sPubK, sID, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedDataInit==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedDataInit, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_VerifySignedDataInit_2).SignMethod, true)
		if intf.(*a1.Request_VerifySignedDataInit_2).SignMethod == a1.SGD_SM3_SM2 ||
			intf.(*a1.Request_VerifySignedDataInit_2).SignMethod == a1.SGD_SM3_RSA {
			equal_bytes("SignerPublicKey", sPubK, intf.(*a1.Request_VerifySignedDataInit_2).SignerPublicKey, false)
			equal_int("SignerIDLen", len(sID), intf.(*a1.Request_VerifySignedDataInit_2).SignerIDLen, false)
			equal_bytes("SignerID", sID, intf.(*a1.Request_VerifySignedDataInit_2).SignerID, false)
		}
		equal_int("InDataLen", len(indata), intf.(*a1.Request_VerifySignedDataInit_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_VerifySignedDataInit_2).InData, false)
	}
}

// 10.ReqType_VerifySignedDataUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 9
	[9] (67 byte) SEQUENCE (5 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 32
		[2] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
		[3] (1 elem)
			INTEGER 8
		[4] (1 elem)
			OCTET STRING (8 byte) testData
	[22] (1 elem)
		UTCTime 2025-04-02 06:41:25 UTC
*/
func TestVerifySignedDataUpdateReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedDataUpdate==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	midhash := []byte("testHashtestHashtestHashtestHash")
	indata := []byte("testData")

	data, err := builder.BuildVerifySignedDataUpdateRequest(sigmthod, midhash, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedDataUpdate==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedDataUpdate, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_VerifySignedDataUpdate_2).SignMethod, true)
		equal_int("HashVauleLen", len(midhash), intf.(*a1.Request_VerifySignedDataUpdate_2).HashVauleLen, false)
		equal_bytes("HashVaule", midhash, intf.(*a1.Request_VerifySignedDataUpdate_2).HashVaule, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_VerifySignedDataUpdate_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_VerifySignedDataUpdate_2).InData, false)
	}
}

// 11.ReqType_VerifySignedDataFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 10
	[10] (796 byte) SEQUENCE (7 elem)
		[2] (1 elem)
			INTEGER 131585
		[3] (1 elem)
			INTEGER 1
		[0] (1 elem)
			SEQUENCE (3 elem)
		[4] (1 elem)
			INTEGER 32
		[6] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
		[5] (1 elem)
			SEQUENCE (2 elem)
				INTEGER (255 bit) 5264753882616949270107378747098155285546805503845970026396009435330698…
				INTEGER (255 bit) 5264753882616949270107378747098155285546805503845970026396009435330698…
		[8] (1 elem)
			INTEGER 2
	[22] (1 elem)
		UTCTime 2025-04-02 06:42:11 UTC
*/
func TestVerifySignedDataFinalReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedDataFinal==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	atype := 1
	var v []byte
	var p *pem.Block
	if atype == 1 {
		crt, _ := os.ReadFile("./ca.crt")
		p, _ = pem.Decode(crt)
		v = p.Bytes
	} else {
		v = []byte("testSerial")
	}
	finalhash := []byte("testHashtestHashtestHashtestHash")
	sig := []byte("testSig1testSig1testSig1testSig1testSig1testSig1testSig1testSig1")
	vfylevel := 2

	data, err := builder.BuildVerifySignedDataFinalRequest(sigmthod, atype, v, finalhash, sig, vfylevel)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedDataFinal==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedDataFinal, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_VerifySignedDataFinal_2).SignMethod, true)

		equal_int("Type", atype, intf.(*a1.Request_VerifySignedDataFinal_2).Type, false)
		if atype == 1 {
			equal_bytes("Cert", v, intf.(*a1.Request_VerifySignedDataFinal_2).Cert.Bytes, true)
		} else {
			equal_bytes("CertSN", v, intf.(*a1.Request_VerifySignedDataFinal_2).CertSN.Bytes, false)
		}
		equal_int("HashValueLen", len(finalhash), intf.(*a1.Request_VerifySignedDataFinal_2).HashValueLen, false)
		equal_bytes("HashValue", finalhash, intf.(*a1.Request_VerifySignedDataFinal_2).HashValue, false)
		sigbytes, _ := a1.Decode_asn1RawSM2Sig_2_bSM2Sig(intf.(*a1.Request_VerifySignedDataFinal_2).Signature)
		equal_bytes("Signature", sig, sigbytes, false)
		equal_int("VerifyLevel", vfylevel, intf.(*a1.Request_VerifySignedDataFinal_2).VerifyLevel, false)
	}
}

// 12.ReqType_SignMessage
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 11
	[11] (55 byte) SEQUENCE (7 elem)
		[5] (1 elem)
			INTEGER 131585
		[6] (1 elem)
			INTEGER 126
		[7] (1 elem)
			OCTET STRING (12 byte) testKeyValue
		[8] (1 elem)
			INTEGER 10
		[9] (1 elem)
			OCTET STRING (10 byte) testInData
		[1] (1 byte) FF
		[3] (1 byte) FF
	[22] (1 elem)
		UTCTime 2025-04-02 06:43:45 UTC
*/
func TestSignMessageReq(t *testing.T) {
	fmt.Println("==================EncodeSignMessage==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	keyidx := 126
	keyValue := []byte("testKeyValue")
	indata := []byte("testInData")
	hashflag := false
	orgText := true
	cerChain := false
	crl := true
	authenAttribute := false

	data, err := builder.BuildSignMessageRequest(sigmthod, keyidx, keyValue, indata,
		hashflag, orgText, cerChain, crl, authenAttribute)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessage==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignMessage, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_SignMessage_2).SignMethod, true)
		equal_int("KeyIndex", keyidx, intf.(*a1.Request_SignMessage_2).KeyIndex, false)
		equal_bytes("KeyValue", keyValue, intf.(*a1.Request_SignMessage_2).KeyValue, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_SignMessage_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_SignMessage_2).InData, false)
		equal_bool("HashFlag", hashflag, intf.(*a1.Request_SignMessage_2).HashFlag)
		equal_bool("OriginalText", orgText, intf.(*a1.Request_SignMessage_2).OriginalText)
		equal_bool("CertificateChain", cerChain, intf.(*a1.Request_SignMessage_2).CertificateChain)
		equal_bool("Crl", crl, intf.(*a1.Request_SignMessage_2).Crl)
		equal_bool("AuthenticationAttributes", authenAttribute, intf.(*a1.Request_SignMessage_2).AuthenticationAttributes)
	}
}

// 13.ReqType_VerifySignedMessage
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 12
	[12] (66 byte) SEQUENCE (6 elem)
		[5] (1 elem)
			INTEGER 10
		[6] (1 elem)
			OCTET STRING (10 byte) testInData
		[7] (1 elem)
			OCTET STRING (32 byte) testSMSGtestSMSGtestSMSGtestSMSG
		[0] (1 byte) FF
		[2] (1 byte) FF
		[4] (1 byte) FF
	[22] (1 elem)
		UTCTime 2025-04-02 06:46:00 UTC
*/
func TestVerifySignedMessageReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessage==================")
	builder := a1.NewSVSRequestBuilder()
	indata := []byte("testInData")
	signedmsg := []byte("testSMSGtestSMSGtestSMSGtestSMSG")
	hashflag := true
	orgText := false
	cerChain := true
	crl := false
	authenAttribute := true

	data, err := builder.BuildVerifySignedMessageRequest(indata, signedmsg,
		hashflag, orgText, cerChain, crl, authenAttribute)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessage==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedMessage, sttype, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_VerifySignedMessage_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_VerifySignedMessage_2).InData, false)
		equal_bytes("SignedMessage", signedmsg, intf.(*a1.Request_VerifySignedMessage_2).SignedMessage, false)
		equal_bool("HashFlag", hashflag, intf.(*a1.Request_VerifySignedMessage_2).HashFlag)
		equal_bool("OriginalText", orgText, intf.(*a1.Request_VerifySignedMessage_2).OriginalText)
		equal_bool("CertificateChain", cerChain, intf.(*a1.Request_VerifySignedMessage_2).CertificateChain)
		equal_bool("Crl", crl, intf.(*a1.Request_VerifySignedMessage_2).Crl)
		equal_bool("AuthenticationAttributes", authenAttribute, intf.(*a1.Request_VerifySignedMessage_2).AuthenticationAttributes)
	}
}

// 14.ReqType_SignMessageInit
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 13
	[13] SEQUENCE (6 elem)
		[3] (1 elem)
			INTEGER 131585
		[0] (10 byte) testPubKey
		[1] (1 byte) 06
		[2] (6 byte) testID
		[4] (1 elem)
			INTEGER 8
		[5] (1 elem)
			OCTET STRING (8 byte) testdata
	[22] (1 elem)
		UTCTime 2025-04-02 06:46:53 UTC
*/
func TestSignMessageInitReq(t *testing.T) {
	fmt.Println("==================EncodeSignMessageInit==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	sPubK := []byte("testPubKey")
	sID := []byte("testID")
	indata := []byte("testdata")

	data, err := builder.BuildSignMessageInitRequest(sigmthod, sPubK, sID, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessageInit==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignMessageInit, sttype, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_SignMessageInit_2).InDataLen, false)
		if intf.(*a1.Request_SignMessageInit_2).SignMethod == a1.SGD_SM3_SM2 ||
			intf.(*a1.Request_SignMessageInit_2).SignMethod == a1.SGD_SM3_RSA {
			equal_bytes("SignerPublicKey", sPubK, intf.(*a1.Request_SignMessageInit_2).SignerPublicKey, false)
			equal_int("SignerIDLen", len(sID), intf.(*a1.Request_SignMessageInit_2).SignerIDLen, false)
			equal_bytes("SignerID", sID, intf.(*a1.Request_SignMessageInit_2).SignerID, false)
		}
		equal_int("InDataLen", len(indata), intf.(*a1.Request_SignMessageInit_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_SignMessageInit_2).InData, false)
	}
}

// 15.ReqType_SignMessageUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 14
	[14] (67 byte) SEQUENCE (5 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 32
		[2] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
		[3] (1 elem)
			INTEGER 8
		[4] (1 elem)
			OCTET STRING (8 byte) testdata
	[22] (1 elem)
		UTCTime 2025-04-02 06:47:54 UTC
*/
func TestSignMessageUpdateReq(t *testing.T) {
	fmt.Println("==================EncodeSignMessageUpdate==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	midhash := []byte("testHashtestHashtestHashtestHash")
	indata := []byte("testdata")

	data, err := builder.BuildSignMessageUpdateRequest(sigmthod, midhash, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessageUpdate==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignMessageUpdate, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_SignMessageUpdate_2).SignMethod, true)
		equal_int("HashVauleLen", len(midhash), intf.(*a1.Request_SignMessageUpdate_2).HashVauleLen, false)
		equal_bytes("HashVaule", midhash, intf.(*a1.Request_SignMessageUpdate_2).HashVaule, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_SignMessageUpdate_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_SignMessageUpdate_2).InData, false)
	}
}

// 16.ReqType_SignMessageFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 15
	[15] (71 byte) SEQUENCE (5 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 126
		[2] (1 elem)
			OCTET STRING (12 byte) testKeyValue
		[3] (1 elem)
			INTEGER 32
		[4] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
	[22] (1 elem)
		UTCTime 2025-04-02 06:48:45 UTC
*/
func TestSignMessageFinalReq(t *testing.T) {
	fmt.Println("==================EncodeSignMessageFinal==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	keyidx := 126
	keyValue := []byte("testKeyValue")
	midhash := []byte("testHashtestHashtestHashtestHash")

	data, err := builder.BuildSignMessageFinalRequest(sigmthod, keyidx, keyValue, midhash)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeSignMessageFinal==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_SignMessageFinal, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_SignMessageFinal_2).SignMethod, true)
		equal_int("KeyIndex", keyidx, intf.(*a1.Request_SignMessageFinal_2).KeyIndex, false)
		equal_bytes("KeyValue", keyValue, intf.(*a1.Request_SignMessageFinal_2).KeyValue, false)
		equal_int("HashVauleLen", len(midhash), intf.(*a1.Request_SignMessageFinal_2).HashVauleLen, false)
		equal_bytes("HashVaule", midhash, intf.(*a1.Request_SignMessageFinal_2).HashVaule, false)
	}
}

// 17.ReqType_VerifySignedMessageInit
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 16
	[16] (49 byte) SEQUENCE (6 elem)
		[3] (1 elem)
			INTEGER 131585
		[0] (10 byte) testPubKey
		[1] (1 byte) 06
		[2] (6 byte) testID
		[4] (1 elem)
			INTEGER 8
		[5] (1 elem)
			OCTET STRING (8 byte) testdata
	[22] (1 elem)
		UTCTime 2025-04-02 06:49:27 UTC
*/
func TestVerifySignedMessageInitReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessageInit==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	sPubK := []byte("testPubKey")
	sID := []byte("testID")
	indata := []byte("testdata")

	data, err := builder.BuildVerifySignedMessageInitRequest(sigmthod, sPubK, sID, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessageInit==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedMessageInit, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_VerifySignedMessageInit_2).SignMethod, true)
		if intf.(*a1.Request_VerifySignedMessageInit_2).SignMethod == a1.SGD_SM3_SM2 ||
			intf.(*a1.Request_VerifySignedMessageInit_2).SignMethod == a1.SGD_SM3_RSA {
			equal_bytes("SignerPublicKey", sPubK, intf.(*a1.Request_VerifySignedMessageInit_2).SignerPublicKey, false)
			equal_int("SignerIDLen", len(sID), intf.(*a1.Request_VerifySignedMessageInit_2).SignerIDLen, false)
			equal_bytes("SignerID", sID, intf.(*a1.Request_VerifySignedMessageInit_2).SignerID, false)
		}
		equal_int("InDataLen", len(indata), intf.(*a1.Request_VerifySignedMessageInit_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_VerifySignedMessageInit_2).InData, false)

	}
}

// 18.ReqType_VerifySignedMessageUpdate
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 17
	[17] (67 byte) SEQUENCE (5 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 32
		[2] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
		[3] (1 elem)
			INTEGER 8
		[4] (1 elem)
			OCTET STRING (8 byte) testdata
	[22] (1 elem)
		UTCTime 2025-04-02 06:50:15 UTC
*/
func TestVerifySignedMessageUpdateReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessageUpdate==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	midhash := []byte("testHashtestHashtestHashtestHash")
	indata := []byte("testdata")

	data, err := builder.BuildVerifySignedMessageUpdateRequest(sigmthod, midhash, indata)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessageUpdate==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedMessageUpdate, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_VerifySignedMessageUpdate_2).SignMethod, true)
		equal_int("HashVauleLen", len(midhash), intf.(*a1.Request_VerifySignedMessageUpdate_2).HashVauleLen, false)
		equal_bytes("HashVaule", midhash, intf.(*a1.Request_VerifySignedMessageUpdate_2).HashVaule, false)
		equal_int("InDataLen", len(indata), intf.(*a1.Request_VerifySignedMessageUpdate_2).InDataLen, false)
		equal_bytes("InData", indata, intf.(*a1.Request_VerifySignedMessageUpdate_2).InData, false)

	}
}

// 19.ReqType_VerifySignedMessageFinal
/*
SEQUENCE (4 elem)
	[20] (1 elem)
		INTEGER 0
	[21] (1 elem)
		INTEGER 18
	[18] (118 byte) SEQUENCE (4 elem)
		[0] (1 elem)
			INTEGER 131585
		[1] (1 elem)
			INTEGER 32
		[2] (1 elem)
			OCTET STRING (32 byte) testHashtestHashtestHashtestHash
		[3] (1 elem)
			OCTET STRING (64 byte) testdatatestdatatestdatatestdatatestdatatestdatatestdatatestdata
	[22] (1 elem)
		UTCTime 2025-04-02 06:51:55 UTC
*/
func TestVerifySignedMessageFinalReq(t *testing.T) {
	fmt.Println("==================EncodeVerifySignedMessageFinal==================")
	builder := a1.NewSVSRequestBuilder()
	sigmthod := a1.SGD_SM3_SM2
	finalhash := []byte("testHashtestHashtestHashtestHash")
	sig := []byte("testdatatestdatatestdatatestdatatestdatatestdatatestdatatestdata")

	data, err := builder.BuildVerifySignedMessageFinalRequest(sigmthod, finalhash, sig)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		fmt.Printf("CreatedDer : \n")
		fmt.Printf("%X\n", data)
	}

	fmt.Println("==================DecodeVerifySignedMessageFinal==================")
	sttype, intf, err := a1.ParseRequest(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else {
		equal_int("ReqType", a1.ReqType_VerifySignedMessageFinal, sttype, false)
		equal_int("SignMethod", sigmthod, intf.(*a1.Request_VerifySignedMessageFinal_2).SignMethod, true)
		equal_int("HashVauleLen", len(finalhash), intf.(*a1.Request_VerifySignedMessageFinal_2).HashVauleLen, false)
		equal_bytes("HashVaule", finalhash, intf.(*a1.Request_VerifySignedMessageFinal_2).HashVaule, false)
		equal_bytes("InData", sig, intf.(*a1.Request_VerifySignedMessageFinal_2).SignedMessage, false)
	}
}
