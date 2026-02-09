//go:build mysql

package sqlop

import (
	"fmt"
	"os"
	b "sig_vfy/src/base"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var User []byte
var UsPwd []byte

const DbIpPort = "tcp(127.0.0.1:3306)"
const DbName = "sigvfy"
const OtherConf = "charset=utf8mb4&parseTime=True&loc=Local"

var Gsqlh *gorm.DB = nil

func init() {
	mm, stderr := b.ReadConfigValues("SQL_USER", "SQL_URPSWD")
	if stderr != nil {
		fmt.Println(stderr.ErrMsg)
		os.Exit(1)
	}
	if user, ok := mm["SQL_USER"].([]byte); ok {
		User = user
	}

	if pwd, ok := mm["SQL_URPSWD"].(int); ok {
		UsPwd = []byte(fmt.Sprintf("%d", pwd))
	} else if pwd, ok := mm["SQL_URPSWD"].([]byte); ok {
		UsPwd = pwd
	}
}

func SqlCreate() *b.StdErr {
	dsn := string(User) + ":" + string(UsPwd) + "@" + DbIpPort + "/" + "?" + OtherConf
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CONNECT_ERROR, err.Error())
	}

	dsn = "CREATE DATABASE IF NOT EXISTS " + DbName
	err = db.Exec(dsn).Error
	if err != nil {
		return b.CreateStdErr(b.SQL_CREATETB_ERROR, err.Error())
	}

	stderr := SqlConnect()
	if stderr != nil {
		return stderr
	}

	err = Gsqlh.AutoMigrate(&SymKey{},
		&EccKey{}, &RsaKey{}, &UserInfo{},
		&IPWhiteTable{}, &ManageLog{}, &ServerLog{},
		&IfDevInited{}, &CAInfo{}, &AppInfo{},
		&AppCert{}, &CACert{}, &AppCertHistory{},
		&WebLog{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CREATETB_ERROR, err.Error())
	}

	var count int64
	Gsqlh.Model(&IfDevInited{}).Count(&count)
	if count == 0 {
		Gsqlh.Create(&IfDevInited{Id: 1, Ifinit: 0})
	}

	return nil
}

func SqlConnect() *b.StdErr {
	dsn := string(User) + ":" + string(UsPwd) + "@" + DbIpPort + "/" + DbName + "?" + OtherConf
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CONNECT_ERROR, err.Error())
	}
	Gsqlh = db

	err = Gsqlh.AutoMigrate(&SymKey{},
		&EccKey{}, &RsaKey{}, &UserInfo{},
		&IPWhiteTable{}, &ManageLog{}, &ServerLog{},
		&IfDevInited{}, &CAInfo{}, &AppInfo{},
		&AppCert{}, &CACert{}, &AppCertHistory{})
	if err != nil {
		return b.CreateStdErr(b.SQL_CREATETB_ERROR, err.Error())
	}

	return nil
}

func SqlDestroy() {
	dsn := string(User) + ":" + string(UsPwd) + "@" + DbIpPort + "/" + "?" + OtherConf
	db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	dsn = "DROP DATABASE IF EXISTS " + DbName
	db.Exec(dsn)
}
