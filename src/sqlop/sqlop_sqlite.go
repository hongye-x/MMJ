//go:build sqlite

package sqlop

import (
	"os"
	b "sig_vfy/src/base"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DbPath = "/usr/local/sqlfile"
var DbName = "/usr/local/sqlfile/sigvfy.db"

var Gsqlh *gorm.DB = nil

func SqlCreate() *b.StdErr {
	os.Mkdir(DbPath, 0755)
	db, err := gorm.Open(sqlite.Open(DbName), &gorm.Config{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CREATEDB_ERROR, "%v", err.Error())
	}

	err = Gsqlh.AutoMigrate(&SymKey{},
		&EccKey{}, &RsaKey{}, &UserInfo{},
		&IPWhiteTable{}, &ManageLog{}, &ServerLog{},
		&IfDevInited{}, &CAInfo{}, &AppInfo{},
		&AppCert{}, &CACert{}, &AppCertHistory{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CREATEDB_ERROR, "%v", err.Error())
	}

	var count int64
	db.Model(&IfDevInited{}).Count(&count)
	if count == 0 {
		db.Create(&IfDevInited{Idx: 1, Ifinit: 0})
	}
	return nil
}

func SqlDestroy() {
	os.Remove(DbName)
	os.Remove(DbPath)
}

func SqlConnect() *b.StdErr {
	db, err := gorm.Open(sqlite.Open(DbName), &gorm.Config{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CONNECT_ERROR, "%v", err.Error())
	}

	err = Gsqlh.AutoMigrate(&SymKey{},
		&EccKey{}, &RsaKey{}, &UserInfo{},
		&IPWhiteTable{}, &ManageLog{}, &ServerLog{},
		&IfDevInited{}, &CAInfo{}, &AppInfo{},
		&AppCert{}, &CACert{}, &AppCertHistory{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CONNECT_ERROR, "%v", err.Error())
	}
	Gsqlh = db
	return nil
}
