package main

type RespStruct struct {
	Code   string `json:"code"`
	Errmsg string `json:"errmsg"`
}

type RespWithInited struct {
	RespStruct
	IfInited int `json:"inited"`
}

type RespWithDiv struct {
	RespStruct
	B64Shadow `json:"b64Shadow"`
}

type RespWithDevinfo struct {
	RespStruct
	BDevInfo `json:"bDevInfo"`
}

type OperInfo struct {
	OperUserType int    `json:"operusertype"`
	OperUuid     string `json:"operuuid"`
}

type B64PubKey struct {
	Bits  int    `json:"bits"`
	B64_X string `json:"x"`
	B64_Y string `json:"y"`
}

type B64Ecsig struct {
	B64_R string `json:"r"`
	B64_S string `json:"s"`
}

type B64Shadow struct {
	B64_S0 string `json:"s0"`
	B64_S1 string `json:"s1"`
	B64_S2 string `json:"s2"`
	B64_S3 string `json:"s3"`
	B64_S4 string `json:"s4"`
}

type BDevInfo struct {
	IssuerName      string  `json:"issuerName"`      // 设备生产厂商名称
	DeviceName      string  `json:"deviceName"`      // 设备型号
	DeviceSerial    string  `json:"deviceSerial"`    // 设备编号
	DeviceVersion   uint    `json:"deviceVersion"`   // 密码设备内部软件版本号
	StandardVersion uint    `json:"standardVersion"` // 密码设备支持的接口规范版本号
	AsymAlgAbility  [2]uint `json:"asymAlgAbility"`  // （非对称算法）前四字节表示支持的算法；后四字节表示算法的最大模长
	SymAlgAbility   uint    `json:"symAlgAbility"`   // （对称算法）所有支持的对称算法
	HashAlgAbility  uint    `json:"hashAlgAbility"`  // 所有支持的杂凑算法
	BufferSize      uint    `json:"bufferSize"`      // 支持的最大文件存储空间
}

type BIFInof struct {
	Name     string `json:"name"`     // 接口名称
	IP       string `json:"ip"`       // IP地址
	Gateway  string `json:"gateway"`  // 网关地址
	Netmask  string `json:"netmask"`  // 子网掩码
	IsActive int    `json:"isActive"` // 网卡是否活跃
}

// 1.
type GenKeyRequest struct {
	OperInfo
	KeyType  int    `json:"keytype"`
	KeyIdx   int    `json:"keyidx"`
	SigORenc int    `json:"sigorenc"`
	KeySize  int    `json:"keysize"`
	Pswd     string `json:"pswd"`
}

// 2.
type DelKeyRequest struct {
	OperInfo
	KeyType  int `json:"keytype"`
	KeyIdx   int `json:"keyidx"`
	SigORenc int `json:"sigorenc"`
}

// 3.
type SetPswdRequest struct {
	OperInfo
	KeyType int    `json:"keytype"`
	KeyIdx  int    `json:"keyidx"`
	Pswd    string `json:"pswd"`
}

// 4.
type CreateUserRequest struct {
	OperInfo
	UserType   int       `json:"usertype"`
	NameORuuid int       `json:"nameORuuid"`
	Value      string    `json:"value"`
	Pin        string    `json:"pin"`
	PubKeyB64  B64PubKey `json:"pubKey"`
}

// 5.
type DelUserRequest struct {
	OperInfo
	NameORuuid int    `json:"nameORuuid"`
	Value      string `json:"value"`
}

// 6.
type VifyUserLoginRequest struct {
	OperUserType int      `json:"operusertype"`
	NameORuuid   int      `json:"nameORuuid"`
	Value        string   `json:"value"`
	Pin          string   `json:"pin"`
	B64Random    string   `json:"random"`
	B64Ecsig     B64Ecsig `json:"ecsig"`
}

// 7.
type SearchIfDevInited OperInfo

// 8.
type GenDevMainKey OperInfo

// 9.
type SetDevInited OperInfo

// 10.

// 11.

// 12.
type KeyDiv struct {
	OperInfo
	DivType  int `json:"divtype"`
	KeyType  int `json:"keytype"`
	KeyIdx   int `json:"keyidx"`
	SigORenc int `json:"sigorenc"`
}

// 13.
type KeyComeBack struct {
	OperInfo
	DivType int `json:"divtype"`
	B64Shadow
}

// 14.
type DevRestartMServer struct {
	OperInfo
}

// 15.
type DevResetAll struct {
	OperInfo
}

// 16.
type DevSelfCheck struct {
	OperInfo
	Flag byte `json:"flag"`
}

// 17.
type DevInfo struct {
	OperInfo
}

// 18.
type WhitTable struct {
	OperInfo
	Cidr string `json:"cidr"`
}

// 19.

// 20.
type Ipv4IfInfo struct {
	OperInfo
}

// ** 通用错误 **//

// 未知错误
const UNKNOW_ERROR int = 0xE8001000

// 文件打开失败
const OPENFILE_ERROR int = 0xE8001001

// 文件读取失败
const READFILE_ERROR int = 0xE8001002

// 数据库连接错误
const SQL_CONNECT_ERROR int = 0xE8001003

// 数据库建库错误
const SQL_CREATETB_ERROR int = 0xE8001004

// 数据库查询误
const SQL_SELECT_ERROR int = 0xE8001005

// 数据库插入错误
const SQL_INSERT_ERROR int = 0xE8001006

// 未知的指令
const UNKNOW_CMD int = 0xE8001007

// 连接数达上限
const OUTOF_MAX_CONNECTION int = 0xE8001008

// 算法自检失败
const ALG_SELF_TEST_ERROR int = 0xE8001009

// 密钥完整性校验失败
const KEY_INTEGRALITY_ERROR int = 0xE800100A

// 连接密码算法服务失败
const CONNECT_TO_CSERVER_ERROR int = 0xE800100B

// 设备还未初始化
const DEV_NOT_INITED int = 0xE800100C

// 无法删除依赖文件
const UNALBE_DEL_DEPENDENCIES int = 0xE800100D

// 获取网卡配置失败
const GET_NET_INFO_ERROR int = 0xE800100E

// 修改网卡配置失败
const MODIFY_NET_INFO_ERROR int = 0xE800100F

// 错误的IP类型
const UNKNOW_IPTYPE int = 0xE8001010

// 拒绝访问
const ACCESS_DENIED int = 0xE8001011

// Rcp调用或注册错误
const RPC_REGORCALL_ERROR int = 0xE8001012

/** keymanage **/
// 密钥类型错误
const KEY_TYPE_ERROR int = 0xE9001001

// 内部存储结构已存在指定索引的密钥
const STORKEY_INTERNAL_EXIST int = 0xE9002002

// 数据库内不存在密钥
const KEY_INSQL_NOEXIST int = 0xE9002003

// 私钥授权码设置失败
const PIV_PIN_SET_ERROR int = 0xE9002004

// 密钥恢复文件错误
const KEY_COMEBAK_FILE_ERROR int = 0xE9002005

// 密钥恢复校验错误
const KEYCB_CHECK_ERROR int = 0xE9002006

/** init **/
// 上电检测随机数文件长度错误
const POWERONDET_RANDLEN_ERROR int = 0xEA001001

// 上电检测不通过
const POWERONDET_RANDRES_ERROR int = 0xEA001002

// 周期检测随机数文件长度错误
const CYCDET_RANDLEN_ERROR int = 0xEA001003

// 周期检测不通过
const CYCDET_RANDRES_ERROR int = 0xEA001004

/** usermanage **/
// 管理员数量超过最大限制
const ADMIN_NUMS_OUTOF_LIMIT int = 0xEB001001

// 操作员数量超过最大限制
const OPERA_NUMS_OUTOF_LIMIT int = 0xEB001002

// 审计员数量超过最大限制
const AUDIT_NUMS_OUTOF_LIMIT int = 0xEB001003

// 用户未注册
const USER_NOT_REGISTERED int = 0xEB001004

// 用户口令错误
const USER_PIN_ERROR int = 0xEB001005

// 不可删除唯一管理员
const ADMIN_CANNOT_DEL int = 0xEB001006

// 用户名和UKEYUUID冲突
const USERNAME_USERUUID_CONFLICT int = 0xEB001007

// 非ASN1类型
const ASN1TYPE_ERROR int = 0xEB001008

/** 0018 **/
const SDR_OK int = 0x0
const SDR_BASE int = 0x01000000
const SDR_UNKNOWERR int = (SDR_BASE + 0x00000001)
const SDR_NOTSUPPORT int = (SDR_BASE + 0x00000002)
const SDR_COMMFAIL int = (SDR_BASE + 0x00000003)
const SDR_HARDFAIL int = (SDR_BASE + 0x00000004)
const SDR_OPENDEVICE int = (SDR_BASE + 0x00000005)
const SDR_OPENSESSION int = (SDR_BASE + 0x00000006)
const SDR_PARDENY int = (SDR_BASE + 0x00000007)
const SDR_KEYNOTEXIST int = (SDR_BASE + 0x00000008)
const SDR_ALGNOTSUPPORT int = (SDR_BASE + 0x00000009)
const SDR_ALGMODNOTSUPPORT int = (SDR_BASE + 0x0000000A)
const SDR_PKOPERR int = (SDR_BASE + 0x0000000B)
const SDR_SKOPERR int = (SDR_BASE + 0x0000000C)
const SDR_SIGNERR int = (SDR_BASE + 0x0000000D)
const SDR_VERIFYERR int = (SDR_BASE + 0x0000000E)
const SDR_SYMOPERR int = (SDR_BASE + 0x0000000F)
const SDR_STEPERR int = (SDR_BASE + 0x00000010)
const SDR_FILESIZEERR int = (SDR_BASE + 0x00000011)
const SDR_FILENOEXIST int = (SDR_BASE + 0x00000012)
const SDR_FILEOFSERR int = (SDR_BASE + 0x00000013)
const SDR_KEYTYPEERR int = (SDR_BASE + 0x00000014)
const SDR_KEYERR int = (SDR_BASE + 0x00000015)
const SDR_ENCDATAERR int = (SDR_BASE + 0x00000016)
const SDR_RANDERR int = (SDR_BASE + 0x00000017)
const SDR_PRKRERR int = (SDR_BASE + 0x00000018)
const SDR_MACERR int = (SDR_BASE + 0x00000019)
const SDR_FILEEXISTS int = (SDR_BASE + 0x0000001A)
const SDR_FILEWERR int = (SDR_BASE + 0x0000001B)
const SDR_NOBUFFER int = (SDR_BASE + 0x0000001C)
const SDR_INARGERR int = (SDR_BASE + 0x0000001D)
const SDR_OUTARGERR int = (SDR_BASE + 0x0000001F)

const SDR_CREATEFILE = 0x01000016
