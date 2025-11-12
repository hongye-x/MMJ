package ISV

import (
	"sig_vfy/src/base"
	"sig_vfy/src/sqlop"
)

// APP数量
const MAX_APP_NUM int = 1024

type MemoryAPPInfo struct {
	Name   []byte
	IP     []byte
	CAName []byte
	Status int
}

var GAPPInfo = make(map[string]*MemoryAPPInfo, MAX_APP_NUM+1) // idx 0 不存

func GetAppListFromSql() ([][]byte, *base.StdErr) {
	var names [][]byte

	err := sqlop.Gsqlh.Model(&sqlop.AppInfo{}).Distinct("name").Pluck("name", &names).Error
	if err != nil {
		return nil, base.CreateStdErr(base.SQL_SELECT_ERROR,
			"%v", err)
	}
	return names, nil
}

func ReloadAppInfoFromSql(name []byte) *base.StdErr {
	var count int64
	err := sqlop.Gsqlh.Model(&sqlop.AppInfo{}).
		Where("name = ?", name).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	if count == 0 {
		return base.CreateStdErr(base.SQL_SELECT_ERROR,
			"No Match Name[%s] Record Code[%08X]", string(name), err)
	} else {
		var sqlappInfo sqlop.AppInfo
		err := sqlop.Gsqlh.Where("name = ?", name).First(&sqlappInfo).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_SELECT_ERROR,
				"Search Name[%s] Error Msg[%v]", string(name), err)
		} else {
			if GAPPInfo[string(name)] == nil {
				GAPPInfo[string(name)] = &MemoryAPPInfo{}
			}
			pcainf := GAPPInfo[string(name)]
			pcainf.Name = sqlappInfo.Name
			pcainf.CAName = sqlappInfo.CAName
			pcainf.Status = sqlappInfo.Status
		}
	}
	return nil
}

func UpdateAppInfo2Sql(appif *MemoryAPPInfo, note []byte) *base.StdErr {
	var count int64
	err := sqlop.Gsqlh.Model(&sqlop.AppInfo{}).
		Where("name = ?", appif.Name).
		Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "%v", err)
	}

	if count == 0 {
		err := sqlop.Gsqlh.Create(&sqlop.AppInfo{Name: appif.Name,
			CAName: appif.CAName, Status: appif.Status, IP: appif.IP,
			Note: note,
		}).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update(Create) App Info Error Details[%v]", err)
		}
	} else if count < int64(MAX_APP_NUM) {
		err := sqlop.Gsqlh.Model(&sqlop.AppInfo{}).
			Where("name = ?", appif.Name).
			Updates(map[string]interface{}{
				"ca_name": appif.CAName,
				"status":  appif.Status,
				"ip":      appif.IP,
				"note":    note,
			}).Error
		if err != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR,
				"Update App Info Error Details[%v]", err)
		}
	} else {
		return base.CreateStdErr(base.GM_APP_NUMS_OUTOF_LIMIT,
			"App Nums Outof Limit[%d] Code[%08X]", MAX_APP_NUM, base.GM_APP_NUMS_OUTOF_LIMIT)
	}
	return nil
}
