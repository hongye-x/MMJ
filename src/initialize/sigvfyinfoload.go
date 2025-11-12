package initialize

import (
	"encoding/base64"
	"encoding/pem"
	"sig_vfy/src/base"
	ISV "sig_vfy/src/sigvfy"
	"sig_vfy/src/sqlop"
)

func CAInfoLoad() *base.StdErr {
	calist, err := ISV.GetCaListFromSql()
	if err != nil {
		return err
	}

	for _, name := range calist {
		var sqlcainfo sqlop.CAInfo
		err := sqlop.Gsqlh.Where("name = ?", name).First(&sqlcainfo).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
		} else {
			strname := string(name)
			ISV.GCaInfo[strname] = &ISV.MemoryCAInfo{
				Name:        sqlcainfo.Name,
				Status:      sqlcainfo.Status,
				DefaultCRL:  sqlcainfo.DefaultCRL,
				DefaultOCSP: sqlcainfo.DefaultOCSP,
				IP:          sqlcainfo.IP,
			}
			if sqlcainfo.RawCRL != nil {
				ISV.GCaInfo[strname].CRL = &ISV.CRLCache{
					URL:         string(sqlcainfo.DefaultCRL),
					RawCRL:      sqlcainfo.RawCRL,
					NextUpdate:  sqlcainfo.NextUpdate,
					LastUpdated: sqlcainfo.LastUpdated,
				}
			}
		}
	}
	return nil
}

func AppInfoLoad() *base.StdErr {
	applist, err := ISV.GetAppListFromSql()
	if err != nil {
		return err
	}

	for _, name := range applist {
		var sqlappinfo sqlop.AppInfo
		err := sqlop.Gsqlh.Where("name = ?", name).First(&sqlappinfo).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
		} else {
			strname := string(name)
			ISV.GAPPInfo[strname] = &ISV.MemoryAPPInfo{
				Name:   sqlappinfo.Name,
				CAName: sqlappinfo.CAName,
				Status: sqlappinfo.Status,
				IP:     sqlappinfo.IP,
			}
		}
	}
	return nil
}

func AppCertInfoLoad() *base.StdErr {
	appcertlist, err := ISV.GetAppCertListFromSql()
	if err != nil {
		return err
	}

	for _, certserial := range appcertlist {
		var sqlappcertinf sqlop.AppCert
		err := sqlop.Gsqlh.Where("cert_serial = ?", certserial).First(&sqlappcertinf).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
		} else {
			bincertserial, _ := base64.StdEncoding.DecodeString(string(certserial))

			ISV.GAppCertInfo[string(certserial)] = &ISV.MemoryAppCertInfo{
				BelongKeyType: sqlappcertinf.BelongKeyType,
				BelongKeyIdx:  sqlappcertinf.BelongKeyIdx,
				BelongKeySV:   sqlappcertinf.BelongKeySV,
				BelongAppName: sqlappcertinf.BelongAppName,
				CertPem:       sqlappcertinf.CertPem,
				CertSerial:    bincertserial,
			}
			if ISV.GAPPInfo[string(sqlappcertinf.BelongAppName)] != nil {
				ISV.GAppCertInfo[string(certserial)].BelongCAName =
					ISV.GAPPInfo[string(sqlappcertinf.BelongAppName)].CAName
			}

			usrcert, _ := pem.Decode(ISV.GAppCertInfo[string(certserial)].CertPem)
			x509usrcert, err := ISV.ParseCert2_x509(usrcert.Bytes)
			if err != nil {
				ISV.GAppCertInfo[string(certserial)].X509Cert = nil
				// log
			} else {
				ISV.GAppCertInfo[string(certserial)].X509Cert = x509usrcert
			}
		}
	}
	return nil
}

func CACertInfoLoad() *base.StdErr {
	cacertlist, err := ISV.GetCACertListFromSql()
	if err != nil {
		return err
	}

	for _, certserial := range cacertlist {
		var sqlcacertinf sqlop.CACert
		err := sqlop.Gsqlh.Where("cert_serial = ?", certserial).First(&sqlcacertinf).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
		} else {
			bincertserial, _ := base64.StdEncoding.DecodeString(string(certserial))
			ISV.GCACertInfo[string(certserial)] = &ISV.MemoryCACertInfo{
				BelongCAName: sqlcacertinf.BelongCAName,
				CertPem:      sqlcacertinf.CertPem,
				CertSerial:   bincertserial,
			}

			cacert, _ := pem.Decode(ISV.GCACertInfo[string(certserial)].CertPem)
			x509cacert, err := ISV.ParseCert2_x509(cacert.Bytes)
			if err != nil {
				ISV.GCACertInfo[string(certserial)].X509Cert = nil
				// log
			} else {
				ISV.GCACertInfo[string(certserial)].X509Cert = x509cacert
			}
			if sqlcacertinf.RawCRL != nil {
				ISV.GCACertInfo[string(certserial)].CRL = &ISV.CRLCache{
					URL:         string(sqlcacertinf.CRLUrl),
					RawCRL:      sqlcacertinf.RawCRL,
					NextUpdate:  sqlcacertinf.NextUpdate,
					LastUpdated: sqlcacertinf.LastUpdated,
				}
			}

		}
	}
	return nil
}
