package ISV

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sig_vfy/src/base"
	"time"
	"unsafe"

	"github.com/tjfoc/gmsm/x509"
)

// CRL下载超时时间
const DOWNLOAD_CRL_OUTTIME = 3

// CRLCache 缓存结构体
type CRLCache struct {
	URL         string
	RawCRL      []byte
	NextUpdate  time.Time
	LastUpdated time.Time
}

func downloadCRL(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: DOWNLOAD_CRL_OUTTIME * time.Second, // 设置超时
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("服务器返回错误状态码: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}

	return data, nil
}

// checkCertificateRevocationByCRL 检查证书吊销状态
func CheckCertificateRevocationByCRL(CAInfo *MemoryCAInfo, cert *x509.Certificate) *base.StdErr {
	var grawcrl []byte
	// 1. 下载或从缓存获取CRL
	err := GetCRLWithCache(CAInfo.CRL, CAInfo.DefaultCRL)
	if err != nil {
		// 无默认CRL
		fmt.Println("default CRL Error")
		if len(cert.CRLDistributionPoints) == 0 {
			// 证书内部无CRLURL
			return base.CreateStdErr(base.GM_NO_CRL_CHECK,
				"Cert Verify Without CRL Code[%08X]", base.GM_NO_CRL_CHECK)
		}
		// 获取证书内部的CRL列表
		rawCRL, err1 := downloadCRL(string(cert.CRLDistributionPoints[0]))
		if err1 != nil {
			return base.CreateStdErr(base.GM_NO_CRL_CHECK,
				"Cert Verify Without CRL Code[%08X]", base.GM_NO_CRL_CHECK)
		}
		grawcrl = rawCRL
	} else {
		grawcrl = CAInfo.CRL.RawCRL
	}
	// 2. 解析CRL
	revokedList, err1 := x509.ParseCRL(grawcrl)
	if err1 != nil {
		return base.CreateStdErr(base.GM_NO_CRL_CHECK,
			"Cert Verify Without CRL Code[%08X]", base.GM_NO_CRL_CHECK)
	}

	// 3. 检查证书序列号是否在吊销列表
	for _, revokedCert := range revokedList.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return base.CreateStdErr(base.GM_ERROR_CERT_REMOVE,
				"Cert Has Been Revoked Code[%08X]", base.GM_ERROR_CERT_REMOVE)
		}
	}
	return nil // 证书未吊销
}

func CheckCertificateRevocationByOCSP(CAInfo *MemoryCAInfo, cert *x509.Certificate) *base.StdErr {
	if len(CAInfo.DefaultOCSP) == 0 && len(cert.OCSPServer) == 0 {
		return base.CreateStdErr(base.GM_NO_OCSP_CHECK,
			"Cert Verify Without OCSP Code[%08X]", base.GM_NO_OCSP_CHECK)
	}

	return base.CreateStdErr(base.GM_NO_OCSP_CHECK,
		"Cert Verify Without OCSP Code[%08X]", base.GM_NO_OCSP_CHECK)
}

// getCRLWithCache 带缓存的CRL下载
func GetCRLWithCache(crlcache *CRLCache, url []byte) *base.StdErr {
	// 检查缓存是否有效
	if crlcache != nil {
		cache1 := crlcache
		if time.Now().Before(cache1.NextUpdate) {
			fmt.Println("使用缓存的CRL文件(有效期至", cache1.NextUpdate.Format("2006-01-02 15:04:05"), ")")
			return nil
		}
	}
	// 下载最新CRL
	rawCRL, err := downloadCRL(string(url))
	if err != nil {
		return base.CreateStdErr(base.GM_CA_CRL_GET_ERROR,
			"Download CRL Error Code[%08X]",
			base.GM_CA_CRL_GET_ERROR)
	}

	// 解析CRL获取NextUpdate时间
	crl, _ := x509.ParseCRL(rawCRL)
	// 更新缓存
	cache := CRLCache{
		URL:         string(url),
		RawCRL:      rawCRL,
		NextUpdate:  crl.TBSCertList.NextUpdate,
		LastUpdated: time.Now(),
	}
	crlcache = &cache
	return nil
}

func CheckCertValidity(cert *x509.Certificate) *base.StdErr {
	now := time.Now()
	// 过期
	if now.After(cert.NotAfter) {
		return base.CreateStdErr(base.GM_ERROR_CERT_INVALID_AF,
			"Cert Lose Efficacy Code[%08X]", base.GM_ERROR_CERT_INVALID_AF)
	}
	// 未生效
	if now.Before(cert.NotBefore) {
		return base.CreateStdErr(base.GM_ERROR_CERT_INVALID_BF,
			"Cert Not Effective Code[%08X]", base.GM_ERROR_CERT_INVALID_BF)
	}

	return nil
}

func ParseCert2_x509(der []byte) (*x509.Certificate, *base.StdErr) {
	x509usercert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, base.CreateStdErr(base.GM_ERROR_CERT_DECODE,
			"Certificate Type Error Code[%08X]", base.GM_ERROR_CERT_DECODE)
	}
	return x509usercert, nil
}

func VerifyCert(sesh unsafe.Pointer, caCertPem, usrCertPem, ID []byte, level int) *base.StdErr {
	usercert, _ := pem.Decode(usrCertPem)
	cacert, _ := pem.Decode(caCertPem)
	x509usercert, _ := ParseCert2_x509(usercert.Bytes)
	x509cacert, _ := ParseCert2_x509(usercert.Bytes)

	// 1.TimeValidty
	stderr := CheckCertValidity(x509usercert)
	if stderr != nil {
		return stderr
	}

	if level == 0 {
		return stderr
	}

	// 2.Vfy
	if x509usercert.SignatureAlgorithm == x509.SM2WithSM3 {
		stderr := VerifyFromDer_SM2(sesh, cacert.Bytes, usercert.Bytes, ID)
		if stderr != nil {
			return stderr
		}
		if level == 1 {
			return stderr
		}

		// 3.CertURL
		caName := x509cacert.SerialNumber.Bytes()
		stderr = CheckCertificateRevocationByCRL(GCaInfo[string(caName)], x509usercert)
		if stderr != nil {
			if stderr.Errcode == base.GM_ERROR_CERT_REMOVE {
				return stderr
			} else {
				stderr := CheckCertificateRevocationByOCSP(GCaInfo[string(caName)], x509usercert)
				if stderr != nil {
					return stderr
				}
			}
		}
		return nil
	} else {
		return base.CreateStdErr(base.GM_UNSUPPORT_SIGALT,
			"Unsupport SignAlg[%08X] Code[%08X]",
			x509usercert.SignatureAlgorithm, base.GM_UNSUPPORT_SIGALT)
	}

}
