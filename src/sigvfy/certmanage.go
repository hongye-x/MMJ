package ISV

import (
	"encoding/base64"
	"encoding/pem"
	"sig_vfy/src/base"
	"sig_vfy/src/sqlop"

	"github.com/tjfoc/gmsm/x509"
)

// AppCert数量
const MAX_APP_CERT_NUM int = 1024

type MemoryAppCertInfo struct {
	BelongKeyType int // 1:rsa 2:sm2
	BelongKeyIdx  int
	BelongKeySV   int // 0:sig 1:enc
	BelongAppName []byte
	BelongCAName  []byte
	CertPem       []byte
	CertSerial    []byte
	X509Cert      *x509.Certificate
}

var GAppCertInfo = make(map[string]*MemoryAppCertInfo, MAX_APP_CERT_NUM)

func GetAppCertListFromSql() ([][]byte, *base.StdErr) {
	var serial [][]byte

	err := sqlop.Gsqlh.Model(&sqlop.AppCert{}).
		Distinct("cert_serial").Pluck("cert_serial", &serial).Error
	if err != nil {
		return nil, base.CreateStdErr(base.SQL_SELECT_ERROR,
			"%v", err)
	}
	return serial, nil
}

func ReloadAppCertInfoFromSql(serial []byte) *base.StdErr {
	var count int64
	b64sn := []byte(base64.StdEncoding.EncodeToString(serial))
	err := sqlop.Gsqlh.Model(&sqlop.AppCert{}).
		Where("cert_serial = ?", b64sn).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	if count == 0 {
		return base.CreateStdErr(base.SQL_SELECT_ERROR,
			"No Match Serial[%08X] Record Code[%08X]", serial, err)
	} else {
		var sqlappCertInfo sqlop.AppCert
		err := sqlop.Gsqlh.Where("cert_serial = ?", b64sn).
			First(&sqlappCertInfo).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR,
				"Search Serial[%08X] Error Msg[%v]", serial, err)
		} else {
			s_serial := string(serial)
			if GAppCertInfo[s_serial] == nil {
				GAppCertInfo[s_serial] = &MemoryAppCertInfo{}
			}
			pcainf := GAppCertInfo[s_serial]
			pcainf.BelongKeyType = sqlappCertInfo.BelongKeyType
			pcainf.BelongKeyIdx = sqlappCertInfo.BelongKeyIdx
			pcainf.BelongKeySV = sqlappCertInfo.BelongKeySV
			pcainf.BelongAppName = sqlappCertInfo.BelongAppName
			pcainf.BelongCAName = GAPPInfo[string(pcainf.BelongAppName)].CAName

			pcainf.CertPem = sqlappCertInfo.CertPem
			appcert, _ := pem.Decode(pcainf.CertPem)
			x509usrcert, err := ParseCert2_x509(appcert.Bytes)
			if err != nil {
				pcainf.X509Cert = nil
				// log
			} else {
				pcainf.X509Cert = x509usrcert
				pcainf.CertSerial = x509usrcert.SerialNumber.Bytes()
			}
		}
	}
	return nil
}

func UpdateAppCertInfo2Sql(appcertif *MemoryAppCertInfo) *base.StdErr {
	var count int64
	b64sn := []byte(base64.StdEncoding.EncodeToString(appcertif.CertSerial))
	err := sqlop.Gsqlh.Model(&sqlop.AppCert{}).
		Where("cert_serial = ?", b64sn).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	if count == 0 {
		err := sqlop.Gsqlh.Create(&sqlop.AppCert{CertSerial: b64sn,
			BelongKeyType: appcertif.BelongKeyType, BelongKeyIdx: appcertif.BelongKeyIdx,
			BelongKeySV: appcertif.BelongKeySV, BelongAppName: appcertif.BelongAppName,
			CertPem: appcertif.CertPem,
		}).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update(Create) AppCert Info Error Details[%v]", err)
		}
	} else if count < int64(MAX_APP_CERT_NUM) {
		err := sqlop.Gsqlh.Model(&sqlop.AppCert{}).
			Where("cert_serial = ?", b64sn).
			Updates(map[string]interface{}{
				"belong_key_type": appcertif.BelongKeyType,
				"belong_key_idx":  appcertif.BelongKeyIdx,
				"belong_key_sv":   appcertif.BelongKeySV,
				"belong_app_name": appcertif.BelongAppName,
				"cert_pem":        appcertif.CertPem,
			}).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update AppCert Info Error Details[%v]", err)
		}
	} else {
		return base.CreateStdErr(base.GM_APP_NUMS_OUTOF_LIMIT,
			"AppCert Nums Outof Limit[%d] Code[%08X]", MAX_APP_CERT_NUM, base.GM_APP_NUMS_OUTOF_LIMIT)
	}
	return nil
}

func GetAppCertSerialByKeyIdx(keytype, keyidx, keysv int) []byte {
	for _, cert := range GAppCertInfo {
		if cert.BelongKeyType == keytype &&
			cert.BelongKeyIdx == keyidx &&
			cert.BelongKeySV == keysv {
			if len(cert.CertSerial) > 0 {
				return cert.CertSerial
			}
		}
	}
	return nil
}

// CACert数量
const MAX_CA_CERT_NUM int = 64

type MemoryCACertInfo struct {
	BelongCAName []byte
	CertPem      []byte
	CertSerial   []byte
	X509Cert     *x509.Certificate
	CRL          *CRLCache
}

var GCACertInfo = make(map[string]*MemoryCACertInfo, MAX_CA_CERT_NUM)

func GetCACertListFromSql() ([][]byte, *base.StdErr) {
	var serial [][]byte

	err := sqlop.Gsqlh.Model(&sqlop.CACert{}).
		Distinct("cert_serial").Pluck("cert_serial", &serial).Error
	if err != nil {
		return nil, base.CreateStdErr(base.SQL_SELECT_ERROR,
			"%v", err)
	}
	return serial, nil
}

func ReloadCACertInfoFromSql(serial []byte) *base.StdErr {
	var count int64
	b64sn := []byte(base64.StdEncoding.EncodeToString(serial))

	err := sqlop.Gsqlh.Model(&sqlop.CACert{}).
		Where("cert_serial = ?", b64sn).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	if count == 0 {
		return base.CreateStdErr(base.SQL_SELECT_ERROR,
			"No Match Serial[%08X] Record Code[%08X]", serial, err)
	} else {
		var sqlCACertInfo sqlop.CACert
		err := sqlop.Gsqlh.Where("cert_serial = ?", b64sn).
			First(&sqlCACertInfo).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR,
				"Search Serial[%08X] Error Msg[%v]", serial, err)
		} else {
			s_serial := string(serial)
			if GCACertInfo[s_serial] == nil {
				GCACertInfo[s_serial] = &MemoryCACertInfo{}
			}
			pcainf := GCACertInfo[s_serial]
			pcainf.CertSerial = serial
			pcainf.BelongCAName = sqlCACertInfo.BelongCAName

			if pcainf.CRL == nil {
				pcainf.CRL = &CRLCache{}
			}
			pcainf.CRL.URL = string(sqlCACertInfo.CRLUrl)
			pcainf.CRL.RawCRL = sqlCACertInfo.RawCRL
			pcainf.CRL.NextUpdate = sqlCACertInfo.NextUpdate
			pcainf.CRL.LastUpdated = sqlCACertInfo.LastUpdated

			pcainf.CertPem = sqlCACertInfo.CertPem
			cacert, _ := pem.Decode(pcainf.CertPem)
			x509cacert, err := ParseCert2_x509(cacert.Bytes)
			if err != nil {
				pcainf.X509Cert = nil
				// log
			} else {
				pcainf.X509Cert = x509cacert
				GetCRLWithCache(pcainf.CRL, []byte(x509cacert.CRLDistributionPoints[0]))
			}
		}
	}
	return nil
}

func UpdatCACertInfo2Sql(cacertif *MemoryCACertInfo) *base.StdErr {
	var count int64
	b64sn := []byte(base64.StdEncoding.EncodeToString(cacertif.CertSerial))
	err := sqlop.Gsqlh.Model(&sqlop.CACert{}).
		Where("cert_serial = ?", b64sn).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	cacert := sqlop.CACert{
		CertSerial:   b64sn,
		BelongCAName: cacertif.BelongCAName,
		CertPem:      cacertif.CertPem,
	}
	if cacertif.CRL != nil {
		cacert.CRLUrl = []byte(cacertif.CRL.URL)
		cacert.RawCRL = cacertif.CRL.RawCRL
		cacert.NextUpdate = cacertif.CRL.NextUpdate
		cacert.LastUpdated = cacertif.CRL.LastUpdated
	}

	if count == 0 {
		err := sqlop.Gsqlh.Create(&cacert).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update(Create) CACert Info Error Details[%v]", err)
		}

	} else if count < int64(MAX_CA_CERT_NUM) {
		err := sqlop.Gsqlh.Model(&sqlop.CACert{}).
			Where("cert_serial = ?", b64sn).
			Updates(cacert).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update CACert Info Error Details[%v]", err)
		}
	} else {
		return base.CreateStdErr(base.GM_CA_NUMS_OUTOF_LIMIT,
			"CACert Nums Outof Limit[%d] Code[%08X]", MAX_CA_CERT_NUM, base.GM_CA_NUMS_OUTOF_LIMIT)
	}
	return nil
}
