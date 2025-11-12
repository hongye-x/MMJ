package ISV

import (
	"sig_vfy/src/base"
	"sig_vfy/src/sqlop"
)

// CA数量
const MAX_CA_NUM int = 64

const CASTATUS_OK int = 0
const CASTATUS_NO_CRL_OCSP int = 1
const CASTATUS_ERROR_CRL_OCSP int = 2
const CASTATUS_DISABLED int = 127

type MemoryCAInfo struct {
	Name        []byte
	IP          []byte
	Status      int
	DefaultOCSP []byte
	DefaultCRL  []byte
	CRL         *CRLCache
}

var GCaInfo = make(map[string]*MemoryCAInfo, MAX_CA_NUM+1) // idx 0 不存

func GetCaListFromSql() ([][]byte, *base.StdErr) {
	var names [][]byte
	err := sqlop.Gsqlh.Model(&sqlop.CAInfo{}).
		Distinct("name").Pluck("name", &names).Error
	if err != nil {
		return nil, base.CreateStdErr(base.SQL_SELECT_ERROR,
			"%v", err)
	}
	return names, nil
}

func ReLoadCaInfoFromSql(name []byte) *base.StdErr {
	var count int64
	err := sqlop.Gsqlh.Model(&sqlop.CAInfo{}).
		Where("name = ?", name).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	if count == 0 {
		return base.CreateStdErr(base.SQL_SELECT_ERROR,
			"No Match Name[%s] Record Code[%08X]", string(name), err)
	} else {
		var sqlCaInfo sqlop.CAInfo
		err := sqlop.Gsqlh.Where("name = ?", name).First(&sqlCaInfo).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR,
				"Search Name[%s] Error Msg[%v]", string(name), err)
		} else {
			if GCaInfo[string(name)] == nil {
				GCaInfo[string(name)] = &MemoryCAInfo{}
			}
			pcainf := GCaInfo[string(name)]
			pcainf.Name = sqlCaInfo.Name
			pcainf.IP = sqlCaInfo.IP
			pcainf.Status = sqlCaInfo.Status
			pcainf.DefaultOCSP = sqlCaInfo.DefaultOCSP
			pcainf.DefaultCRL = sqlCaInfo.DefaultCRL
			if pcainf.CRL == nil {
				pcainf.CRL = &CRLCache{}
			}
			pcainf.CRL.URL = string(sqlCaInfo.DefaultCRL)
			pcainf.CRL.RawCRL = sqlCaInfo.RawCRL
			pcainf.CRL.NextUpdate = sqlCaInfo.NextUpdate
			pcainf.CRL.LastUpdated = sqlCaInfo.LastUpdated
		}
	}
	return nil
}

func UpdateCaInfo2Sql(cif *MemoryCAInfo, note []byte) *base.StdErr {
	var count int64
	err := sqlop.Gsqlh.Model(&sqlop.CAInfo{}).
		Where("name = ?", cif.Name).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	sqlcif := sqlop.CAInfo{
		Name:        cif.Name,
		IP:          cif.IP,
		Status:      cif.Status,
		DefaultOCSP: cif.DefaultOCSP,
		DefaultCRL:  cif.DefaultCRL,
		Note:        note}
	if cif.CRL != nil {
		sqlcif.DefaultCRL = []byte(cif.DefaultCRL)
		sqlcif.RawCRL = cif.CRL.RawCRL
		sqlcif.NextUpdate = cif.CRL.NextUpdate
		sqlcif.LastUpdated = cif.CRL.LastUpdated
	}

	if count == 0 {
		err := sqlop.Gsqlh.Create(&sqlcif).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update(Create) CA Info Error Details[%v]", err)
		}
	} else if count < (int64)(MAX_CA_NUM) {
		err := sqlop.Gsqlh.Model(&sqlop.CAInfo{}).Where("name = ?", cif.Name).
			Updates(sqlcif).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update CA Info Error Details[%v]", err)
		}
	} else {
		return base.CreateStdErr(base.GM_CA_NUMS_OUTOF_LIMIT,
			"CA Nums Outof Limit[%d] Code[%08X]", MAX_CA_NUM, base.GM_CA_NUMS_OUTOF_LIMIT)
	}
	return nil
}
