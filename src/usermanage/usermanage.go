package usermanage

import (
	"bytes"
	"encoding/base64"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"sig_vfy/src/sqlop"
	"unsafe"

	"gorm.io/gorm"
)

// 管理员最大数量
const USER_ADMIN_MAX = 3
const USER_TYPE_ADMIN = 0

// 操作员最大数量
const USER_OPERA_MAX = 5
const USER_TYPE_OPERA = 1

// 审计员最大数量
const USER_ADUIT_MAX = 3
const USER_TYPE_AUDIT = 2

// salt
var salt = []byte("12120909JKLHd")

func checkUserExistInSql(name, uuid []byte) (int, *b.StdErr) {
	if name != nil && uuid != nil {
		return 0, b.CreateStdErr(b.ADMIN_NUMS_OUTOF_LIMIT, "Create User Error Use Name Or UUID")
	}
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return 0, err
		}
	}
	var count int64
	var errno = b.SQL_SELECT_ERROR
	var err error
	if uuid != nil {
		b64uuid := base64.StdEncoding.EncodeToString(uuid)
		err = sqlop.Gsqlh.Model(&sqlop.UserInfo{}).
			Where("user_uuid = ?", b64uuid).Count(&count).Error
	} else {
		err = sqlop.Gsqlh.Model(&sqlop.UserInfo{}).
			Where("user_name = ?", name).Count(&count).Error
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return 0, b.CreateStdErr(errno, "%v", err)
	}
	return int(count), nil
}

func getUserNums(usertype int) (int, *b.StdErr) {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return 0, err
		}
	}

	var count int64
	var errno = b.SQL_SELECT_ERROR
	err := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).
		Where("user_type = ?", usertype).Count(&count).Error

	if err != nil && err != gorm.ErrRecordNotFound {
		return 0, b.CreateStdErr(errno, "%v", err)
	}

	return int(count), nil
}

func CreateUser(sesh unsafe.Pointer, usertype int, name, uuid []byte, pin []byte,
	pubKey *ISDF.ECCrefPublicKey) *b.StdErr {
	if name != nil && uuid != nil {
		return b.CreateStdErr(b.USERNAME_USERUUID_CONFLICT, "Create User Error Use Name Or UUID")
	}

	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return err
		}
	}

	nums, stderr := getUserNums(usertype)
	if stderr != nil {
		return stderr
	}
	if usertype == USER_TYPE_ADMIN {
		if nums >= USER_ADMIN_MAX {
			return b.CreateStdErr(b.ADMIN_NUMS_OUTOF_LIMIT, "Create User Error Type Admin Outof Limit")
		}
	} else if usertype == USER_TYPE_OPERA {
		if nums >= USER_OPERA_MAX {
			return b.CreateStdErr(b.OPERA_NUMS_OUTOF_LIMIT, "Create User Error Type Operater Outof Limit")
		}
	} else if usertype == USER_TYPE_AUDIT {
		if nums >= USER_ADUIT_MAX {
			return b.CreateStdErr(b.AUDIT_NUMS_OUTOF_LIMIT, "Create User Error Type Audit Outof Limit")
		}
	}

	if uuid != nil {
		b64uuid := base64.StdEncoding.EncodeToString(uuid)
		_, stderr = checkUserExistInSql(nil, []byte(b64uuid))
		if stderr != nil {
			return stderr
		}
		pindigest, uiret := ISDF.Hash(sesh, append(pin, salt...))
		if uiret != 0 {
			return b.CreateStdErr(uiret, "Create User SDF Func Error")
		}
		b64pindigest := base64.StdEncoding.EncodeToString(pindigest)
		pubkV := b.ConcatSlices(pubKey.X[:], pubKey.Y[:])
		b64pubkV := base64.StdEncoding.EncodeToString(pubkV)

		err := sqlop.Gsqlh.Create(&sqlop.UserInfo{UserType: usertype, UserUUID: []byte(b64uuid),
			UserPin: []byte(b64pindigest), UserPubkey: []byte(b64pubkV)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v", err)
		}
	} else {
		realname := bytes.TrimRight(name, "\x00")
		_, stderr = checkUserExistInSql(realname, nil)
		if stderr != nil {
			return stderr
		}
		pindigest, uiret := ISDF.Hash(sesh, append(pin, salt...))
		if uiret != 0 {
			return b.CreateStdErr(uiret, "Create User SDF Func Error")
		}
		b64pindigest := base64.StdEncoding.EncodeToString(pindigest)

		err := sqlop.Gsqlh.Create(&sqlop.UserInfo{UserType: usertype, UserName: realname,
			UserPin: []byte(b64pindigest)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v", err)
		}
	}
	return nil
}

func DelUser(name, uuid []byte) *b.StdErr {
	if name != nil && uuid != nil {
		return b.CreateStdErr(b.USERNAME_USERUUID_CONFLICT, "Del User Error Use Name Or UUID")
	}
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return err
		}
	}

	var userType int
	if uuid != nil {
		b64uuid := base64.StdEncoding.EncodeToString(uuid)
		res := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).
			Where("user_uuid = ?", b64uuid).
			Pluck("user_type", &userType)
		if res.Error != nil || res.RowsAffected == 0 {
			return b.CreateStdErr(b.SQL_SELECT_ERROR, "User Del Error No Match UUID")
		}

		if userType == USER_TYPE_ADMIN {
			var adminCount int64
			err := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).
				Where("user_type = ?", USER_TYPE_ADMIN).
				Count(&adminCount).Error
			if err != nil {
				return b.CreateStdErr(b.SQL_SELECT_ERROR, "%v", err)
			}

			if adminCount == 1 {
				return b.CreateStdErr(b.ADMIN_CANNOT_DEL, "User Del Error Cannot Delete The Only Admin User")
			}
		}
		sqlop.Gsqlh.Model(&sqlop.UserInfo{}).Where("user_uuid = ?", b64uuid).Delete(&sqlop.UserInfo{})
	} else {
		realname := bytes.TrimRight(name, "\x00")
		res := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).
			Where("user_name = ?", string(realname)).
			Pluck("user_type", &userType)
		if res.Error != nil || res.RowsAffected == 0 {
			return b.CreateStdErr(b.SQL_SELECT_ERROR, "User Del Error No Match UserName")
		}

		if userType == USER_TYPE_ADMIN {
			var adminCount int64
			err := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).
				Where("user_type = ?", USER_TYPE_ADMIN).
				Count(&adminCount).Error
			if err != nil {
				return b.CreateStdErr(b.SQL_SELECT_ERROR, "%v", err)
			}

			if adminCount == 1 {
				return b.CreateStdErr(b.ADMIN_CANNOT_DEL, "User Del Error Cannot Delete The Only Admin User")
			}
		}
		sqlop.Gsqlh.Model(&sqlop.UserInfo{}).Where("user_name = ?", string(realname)).Delete(&sqlop.UserInfo{})
	}
	return nil
}

func UserVerify(sesh unsafe.Pointer, name, uuid []byte, pin []byte,
	random []byte, ecsig *ISDF.ECCSignature) (int, *b.StdErr) {
	if name != nil && uuid != nil {
		return 0, b.CreateStdErr(b.USERNAME_USERUUID_CONFLICT, "Verify User Error Use Name Or UUID")
	}

	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return 0, err
		}
	}

	var userIfV sqlop.UserInfo
	if uuid != nil {
		b64uuid := base64.StdEncoding.EncodeToString(uuid)
		err := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).Where("user_uuid = ?", b64uuid).First(&userIfV).Error
		if err != nil {
			return 0, b.CreateStdErr(b.USER_NOT_REGISTERED, "User Verify Error User Not Registered")
		}

		pindigest, uiret := ISDF.Hash(sesh, append(pin, salt...))
		if uiret != 0 {
			return 0, b.CreateStdErr(uiret, "User Verify Error")
		}

		b64pindigest := base64.StdEncoding.EncodeToString(pindigest)
		if !bytes.Equal(userIfV.UserPin, []byte(b64pindigest)) {
			return 0, b.CreateStdErr(b.USER_PIN_ERROR, "User Verify Error User Pin Error")
		}

		var userpubk ISDF.ECCrefPublicKey
		userpubk.Bits = 256
		binpubk, _ := base64.StdEncoding.DecodeString(string(userIfV.UserPubkey))
		userpubk.X = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&binpubk[0]))
		userpubk.Y = *(*[ISDF.ECCref_MAX_LEN]byte)(unsafe.Pointer(&binpubk[ISDF.ECCref_MAX_LEN]))

		rdigst, uiret := ISDF.Hash(sesh, random)
		if uiret != 0 {
			return 0, b.CreateStdErr(uiret, "User Verify Error")
		}

		uiret = ISDF.ExternalVerifyECC(sesh, ISDF.SGD_SM2, &userpubk, rdigst, ecsig)
		if uiret != 0 {
			return 0, b.CreateStdErr(uiret, "User Verify Error")
		}
	} else {
		realname := string(bytes.TrimRight(name, "\x00"))
		err := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).Where("user_name = ?", string(realname)).First(&userIfV).Error
		if err != nil {
			return 0, b.CreateStdErr(b.USER_NOT_REGISTERED, "User Verify Error User Not Registered")
		}

		pindigest, uiret := ISDF.Hash(sesh, append(pin, salt...))
		if uiret != 0 {
			return 0, b.CreateStdErr(uiret, "User Verify Error")
		}

		b64pindigest := base64.StdEncoding.EncodeToString(pindigest)
		if !bytes.Equal(userIfV.UserPin, []byte(b64pindigest)) {
			return 0, b.CreateStdErr(b.USER_PIN_ERROR, "User Verify Error User Pin Error")
		}
	}
	return userIfV.UserType, nil
}

func GetUserList() ([]sqlop.UserInfo, *b.StdErr) {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return nil, err
		}
	}
	var users []sqlop.UserInfo
	err := sqlop.Gsqlh.Model(&sqlop.UserInfo{}).Find(&users).Error
	if err != nil {
		return nil, b.CreateStdErr(b.SQL_SELECT_ERROR, "%v", err)
	}

	return users, nil
}
