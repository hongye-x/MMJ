package sqlop

import "time"

// General
type SymKey struct {
	KeyIdx    int    `gorm:"column:key_idx;primaryKey;autoIncrement:false"`
	KeyBits   int    `gorm:"column:key_bits;not null"`
	KeyValue  []byte `gorm:"column:key_value"`
	KeyDigest []byte `gorm:"column:key_digest"`
}

type EccKey struct {
	KeyIdx          int    `gorm:"column:key_idx;primaryKey;autoIncrement:false"`
	KeyBits         int    `gorm:"column:key_bits;not null"`
	PrivKeyAuth     int    `gorm:"column:priv_key_auth"`
	PrivKeyAuthCode []byte `gorm:"column:priv_key_auth_code"`
	PubKeyValue     []byte `gorm:"column:pub_key_value"`
	PivKeyValue     []byte `gorm:"column:piv_key_value"`
	KeyDigest       []byte `gorm:"column:key_digest"`
}

type RsaKey struct {
	KeyIdx          int    `gorm:"column:key_idx;primaryKey;autoIncrement:false"`
	KeyBits         int    `gorm:"column:key_bits;not null"`
	PrivKeyAuth     int    `gorm:"column:priv_key_auth"`
	PrivKeyAuthCode []byte `gorm:"column:priv_key_auth_code"`
	PubKeyValue     []byte `gorm:"column:pub_key_value"`
	PivKeyValue     []byte `gorm:"column:piv_key_value"`
	KeyDigest       []byte `gorm:"column:key_digest"`
}

type UserInfo struct {
	Id         int    `gorm:"column:id;primaryKey;autoIncrement:true"`
	UserType   int    `gorm:"column:user_type;not null"`
	UserUUID   []byte `gorm:"column:user_uuid;type:varbinary(64);uniqueIndex"`
	UserName   []byte `gorm:"column:user_name;type:varbinary(32);uniqueIndex"`
	UserPin    []byte `gorm:"column:user_pin;not null"`
	UserPubkey []byte `gorm:"column:user_pubk;"`
}

type IPWhiteTable struct {
	Id int    `gorm:"column:id;primaryKey;autoIncrement:true"`
	IP []byte `gorm:"column:ip;not null"`
}

type ManageLog struct {
	Id             uint      `gorm:"column:id;primaryKey;autoIncrement:true"`
	LogLevel       []byte    `gorm:"column:log_level;not null"`
	UserType       int       `gorm:"column:user_type;not null"`
	UserNameOrUUID []byte    `gorm:"column:user_name_or_uuid;not null;type:varbinary(32);"`
	Message        string    `gorm:"column:message"`
	RecordTime     time.Time `gorm:"column:record_time;autoCreateTime;type:timestamp;precision:3"` //type:timestamp Unix时间戳 precision:3 精度毫秒
}

type ServerLog struct {
	Id         uint      `gorm:"primaryKey;autoIncrement:true"`
	LogLevel   []byte    `gorm:"column:log_level;not null"`
	UserIp     []byte    `gorm:"column:user_ip;not null"`
	Message    string    `gorm:"column:message"`
	RecordTime time.Time `gorm:"column:record_time;autoCreateTime;type:timestamp;precision:3"` //type:timestamp Unix时间戳 precision:3 精度毫秒
}

type IfDevInited struct {
	Id     int `gorm:"column:id;primaryKey;autoIncrement:true"`
	Ifinit int `gorm:"column:ifinit"`
}

// SigVfy
type CAInfo struct {
	Id          int       `gorm:"column:id;primaryKey;autoIncrement:true"`
	Name        []byte    `gorm:"column:name;type:varbinary(32);uniqueIndex"`
	IP          []byte    `gorm:"column:ip"`
	Status      int       `gorm:"column:status;not null"`
	DefaultCRL  []byte    `gorm:"column:default_crl"`
	RawCRL      []byte    `gorm:"column:raw_crl"`
	NextUpdate  time.Time `gorm:"column:crl_next_update"`
	LastUpdated time.Time `gorm:"column:crl_last_update"`
	DefaultOCSP []byte    `gorm:"column:default_ocsp"`
	Note        []byte    `gorm:"column:note"`
}

type AppInfo struct {
	Id   int    `gorm:"column:id;primaryKey;autoIncrement:true"`
	Name []byte `gorm:"column:name;type:varbinary(32);uniqueIndex"`
	// Relate CA By Idx
	IP []byte `gorm:"column:ip"`

	CAName []byte `gorm:"column:ca_name"`
	// KeyStorage Idx
	Status int `gorm:"column:status;not null"`
	// extra
	Note []byte `gorm:"column:note"`
}

type AppCert struct {
	Id            int    `gorm:"column:id;primaryKey;autoIncrement:true"`
	CertSerial    []byte `gorm:"column:cert_serial;type:varbinary(128);uniqueIndex"`
	BelongKeyType int    `gorm:"column:belong_key_type;"`
	BelongKeyIdx  int    `gorm:"column:belong_key_idx;"`
	BelongKeySV   int    `gorm:"column:belong_key_sv;"`
	BelongAppName []byte `gorm:"column:belong_app_name"`
	CertPem       []byte `gorm:"column:cert_pem"`
}

type CACert struct {
	Id           int       `gorm:"column:id;primaryKey;autoIncrement:true"`
	CertSerial   []byte    `gorm:"column:cert_serial;type:varbinary(128);uniqueIndex"`
	BelongCAName []byte    `gorm:"column:belong_ca_name"`
	CertPem      []byte    `gorm:"column:cert_pem"`
	CRLUrl       []byte    `gorm:"column:crl_url"`
	RawCRL       []byte    `gorm:"column:raw_crl"`
	NextUpdate   time.Time `gorm:"column:crl_next_update"`
	LastUpdated  time.Time `gorm:"column:crl_last_update"`
}

type AppCertHistory struct {
	Idx            int       `gorm:"column:idx;primaryKey;autoIncrement:true"`
	BelongUserName []byte    `gorm:"column:belong_user_name"`
	CertPem        []byte    `gorm:"column:cert_pem"`
	FailureTime    time.Time `gorm:"column:failure_time"`
	FailureReason  []byte    `gorm:"column:failure_reason"`
}
