package ISV

/*
#cgo CFLAGS:
#cgo LDFLAGS:-L /root/mmj/sig_vfy/lib -lgmssl -lsoftsdf
#include <gmssl/sm2.h>
#include <gmssl/x509.h>
#include <gmssl/x509_cer.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>
#include <gmssl/sm2_z256.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct ECCrefPublicKey_st
{
	unsigned int bits;
	unsigned char x[64];
	unsigned char y[64];
} ECCrefPublicKey;


typedef struct {
    int version;
    const uint8_t *serial;
    size_t serial_len;
    int signature_algor;
    const uint8_t *issuer;
    size_t issuer_len;
    time_t not_before;
    time_t not_after;
    const uint8_t *subject;
    size_t subject_len;
    ECCrefPublicKey subject_public_key;
    const uint8_t *issuer_unique_id;
    size_t issuer_unique_id_len;
    const uint8_t *subject_unique_id;
    size_t subject_unique_id_len;
    const uint8_t *exts;
    size_t exts_len;
} X509TBSInfo;

int parse_tbs_from_der(X509TBSInfo *info, uint8_t *outsig, uint8_t *outtbs,uint32_t *outtbslen, uint8_t *der_data, size_t der_data_len) {
	int ret = 0;

	unsigned char tbs[1024];
    const uint8_t *ptbs = &tbs[0];
    size_t tbslen = 0;
    int algor = 0;
    unsigned char sig[72];
    const uint8_t *psig = &sig[0];
    size_t siglen = 0;
    const uint8_t *pusrcertder = &der_data[0];
    ret = x509_signed_from_der(&ptbs,&tbslen,&algor,
    &psig,&siglen,&pusrcertder,&der_data_len);
    if (ret != 1) {
        fprintf(stderr, "x509_signed_from_der failed, ret = %d\n", ret);
        return -1;
    }
	memcpy(outtbs, ptbs, tbslen);
	*outtbslen=tbslen;

	SM2_SIGNATURE sm2sig;
	ret = sm2_signature_from_der(&sm2sig,&psig,&siglen);
 	if (ret != 1) {
        fprintf(stderr, "sm2_signature_from_der failed, ret = %d\n", ret);
        return -1;
    }
	memcpy(outsig,sm2sig.r,32);
	memcpy(outsig+32,sm2sig.s,32);


    int version1 = 0; // 证书版本号
    const uint8_t *serial1 = NULL; // 序列号指针
    size_t serial_len1 = 0; // 序列号长度
    int signature_algor1 = 0; // 签名算法标识
    const uint8_t *issuer1 = NULL; // 颁发者信息指针
    size_t issuer_len1 = 0; // 颁发者信息长度
    time_t not_before1 = 0; // 证书生效时间
    time_t not_after1 = 0; // 证书失效时间
    const uint8_t *subject1 = NULL; // 主题（持证者）信息指针
    size_t subject_len1 = 0; // 主题信息长度
    SM2_KEY subject_public_key1; // 主题公钥
    const uint8_t *issuer_unique_id1 = NULL; // 颁发者唯一标识
    size_t issuer_unique_id_len1 = 0; // 颁发者唯一标识长度
    const uint8_t *subject_unique_id1 = NULL; // 主题唯一标识
    size_t subject_unique_id_len1 = 0; // 主题唯一标识长度
    const uint8_t *exts1 = NULL; // 扩展字段
    size_t exts_len1 = 0; // 扩展字段长度

    // 假设 der_data 已经被赋值，例如从文件读取
    ret = x509_tbs_cert_from_der(&version1, &serial1, &serial_len1, &signature_algor1,
                                     &issuer1, &issuer_len1, &not_before1, &not_after1,
                                     &subject1, &subject_len1, &subject_public_key1,
                                     &issuer_unique_id1, &issuer_unique_id_len1,
                                     &subject_unique_id1, &subject_unique_id_len1,
                                     &exts1, &exts_len1, &ptbs, &tbslen);

    if (ret != 1) {
        printf("解析 TBS 证书失败\n");
        return -1;
    }
	info->version = version1;
	info->serial = serial1;
	info->serial_len = serial_len1;
	info->signature_algor = signature_algor1;
	info->issuer = issuer1;
	info->issuer_len = issuer_len1;
	info->not_before = not_before1;
	info->not_after = not_after1;
	info->subject = subject1;
	info->subject_len = subject_len1;
	info->issuer_unique_id = issuer_unique_id1;
	info->issuer_unique_id_len = issuer_unique_id_len1;
	info->subject_unique_id = subject_unique_id1;
	info->subject_unique_id_len = subject_unique_id_len1;
	info->exts = exts1;
	info->exts_len = exts_len1;

	// sm2_key_print(stdout,0,0,"PUBKEY",&subject_public_key1);
    SM2_POINT public_key;
    sm2_z256_point_to_bytes(&subject_public_key1.public_key,  (uint8_t *)&public_key);
	info->subject_public_key.bits = 256;
	memcpy(&info->subject_public_key.x[32],public_key.x,32);
	memcpy(&info->subject_public_key.y[32],public_key.y,32);
	return 1;
}

int check_if_cert_issure_belong_root(unsigned char *usercertder,unsigned int usercertderlen,
    unsigned char *cacertder,unsigned int cacertderlen){
    const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;
    if (x509_cert_get_issuer(usercertder, usercertderlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject(cacertder, cacertderlen, &subject, &subject_len) != 1
		|| x509_name_equ(issuer, issuer_len, subject, subject_len) != 1) {
		return -1;
	}
    return 1;
}

*/
import "C"
import (
	"fmt"
	"sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"unsafe"
)

type X509TBSInfo struct {
	Version         int
	Serial          []byte
	SignatureAlgor  int
	Issuer          []byte
	NotBefore       int64
	NotAfter        int64
	Subject         []byte
	PublicKey       ISDF.ECCrefPublicKey
	IssuerUniqueID  []byte
	SubjectUniqueID []byte
	Exts            []byte
}

func nilIfNull(ptr *C.uint8_t, length C.size_t) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}

// return tbs,ecsig,tbsbyte
func ParseTBSFromDER(derData []byte) (*X509TBSInfo, *ISDF.ECCSignature, []byte, *base.StdErr) {
	var info C.X509TBSInfo
	var csig []byte = make([]byte, 64)
	var btbs []byte = make([]byte, 1024)
	var tbslen C.uint32_t
	ret := C.parse_tbs_from_der(&info, (*C.uint8_t)(unsafe.Pointer(&csig[0])), (*C.uint8_t)(unsafe.Pointer(&btbs[0])), &tbslen,
		(*C.uint8_t)(unsafe.Pointer(&derData[0])), C.size_t(len(derData)))
	if ret != 1 {
		return nil, nil, nil, base.CreateStdErr(base.GM_ERROR_CERT_DECODE,
			"Parse TBS Error Code [%08X]", base.GM_ERROR_CERT_DECODE)
	}

	tbs := &X509TBSInfo{
		Version:        int(info.version),
		Serial:         nilIfNull(info.serial, info.serial_len),
		SignatureAlgor: int(info.signature_algor),
		Issuer:         nilIfNull(info.issuer, info.issuer_len),
		NotBefore:      int64(info.not_before),
		NotAfter:       int64(info.not_after),
		Subject:        nilIfNull(info.subject, info.subject_len),
		Exts:           nilIfNull(info.exts, info.exts_len),
	}

	tbs.PublicKey.Bits = uint(info.subject_public_key.bits)
	C.memcpy(unsafe.Pointer(&tbs.PublicKey.X[32]), unsafe.Pointer(&info.subject_public_key.x[32]), 32)
	C.memcpy(unsafe.Pointer(&tbs.PublicKey.Y[32]), unsafe.Pointer(&info.subject_public_key.y[32]), 32)
	var ecsig ISDF.ECCSignature
	copy(ecsig.R[32:], csig[:32])
	copy(ecsig.S[32:], csig[32:])

	return tbs, &ecsig, btbs[:tbslen], nil
}

func check_ifbelong_root(cacert, usrcert []byte) *base.StdErr {
	var cacertlen = len(cacert)
	var usrcertlen = len(usrcert)
	iret := C.check_if_cert_issure_belong_root((*C.uchar)(unsafe.Pointer(&usrcert[0])), (C.uint)(usrcertlen),
		(*C.uchar)(unsafe.Pointer(&cacert[0])), (C.uint)(cacertlen))
	if iret != 1 {
		fmt.Println("check_ifbelong_root error")
	}
	return nil
}

// certder
func VerifyFromDer_SM2(sesh unsafe.Pointer, cacert, usrcert, usrid []byte) *base.StdErr {
	var iuserid []byte = []byte(base.SM2_DEFAULT_ID)
	if len(usrid) != 0 {
		iuserid = usrid
	}

	// 判断从属关系
	stderr := check_ifbelong_root(cacert, usrcert)
	if stderr != nil {
		return stderr
	}

	// 最终验签
	cacertinfo, _, _, stderr := ParseTBSFromDER(cacert)
	if stderr != nil {
		return stderr
	}

	_, usersig, usertbs, stderr := ParseTBSFromDER(usrcert)
	if stderr != nil {
		return stderr
	}

	iret := ISDF.HashInit(sesh, ISDF.SGD_SM3, &cacertinfo.PublicKey, iuserid)
	if iret != 0 {
		return base.CreateStdErr(iret, "Verify Cert Error Code [%08X]", iret)
	}
	iret = ISDF.HashUpdate(sesh, usertbs)
	if iret != 0 {
		return base.CreateStdErr(iret, "Verify Cert Error Code [%08X]", iret)
	}
	cachash, iret := ISDF.HashFinal(sesh)
	if iret != 0 {
		return base.CreateStdErr(iret, "Verify Cert Error Code [%08X]", iret)
	}

	iret = ISDF.ExternalVerifyECC(sesh, ISDF.SGD_SM2_1, &cacertinfo.PublicKey, cachash, usersig)
	if iret != 0 {
		return base.CreateStdErr(iret, "Verify Cert Error Code [%08X]", iret)
	}
	return nil
}
