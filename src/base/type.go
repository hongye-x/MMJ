package base

/** common **/
// 单次最大接收长度
const RECVMAXLEN_ONCE int = 1024 * 1024 * 16 // 16M

// 最大连接数
const MAX_CONNECTION int = 1000

// 最大对称密钥存储数量
const MAX_SYM_KEY_NUM int = 1000

// 最大RSA密钥存储数量
const MAX_RSA_KEY_NUM int = 1000

// 最大SM2密钥存储数量
const MAX_SM2_KEY_NUM int = 1000

/** init **/
// 上电检测轮数
const POD_CYCLE int = 20

// 上电检测单轮数据长度
const POD_PERBITLEN int = 1000000

// 上电检测最低通过率
const POD_PASSRATE float32 = 0.95

// 周期检测轮数
const CYC_CYCLE int = 20

// 周期检测单轮数据长度
const CYC_PERBITLEN int = 20000

// 周期检测最低通过率
const CYC_PASSRATE float32 = 0.95

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

/** sig&vfy **/
const GM_SUCESS int = 0x0                       // 正常返回
const GM_ERROR_BASE int = 0x04000000            // 错误码起始值
const GM_ERROR_CERT_ID int = 0x04000001         // 错误的证书标识
const GM_ERROR_CERT_INFO_TYPE int = 0x04000002  // 错误的证书信息类型
const GM_ERROR_SERVER_CONNECT int = 0x04000003  // CRL或OCSP无法连接
const GM_ERROR_SIGN_METHOD int = 0x04000004     // 签名算法类型错误
const GM_ERROR_KEY_INDEX int = 0x04000005       // 错误的密钥标识
const GM_ERROR_KEY_VALUE int = 0x04000006       // 密钥访问控制码错误
const GM_ERROR_CERT_DECODE int = 0x04000008     // 证书解析失败
const GM_ERROR_CERT int = 0x04000007            // 证书非法或不存在
const GM_ERROR_CERT_INVALID_AF int = 0x04000009 // 证书过期
const GM_ERROR_CERT_INVALID_BF int = 0x0400000A // 证书尚未生效
const GM_ERROR_CERT_REMOVE int = 0x0400000B     // 证书被吊销
const GM_INVALID_SIGNATURE int = 0x0400000C     // 签名无效
const GM_INVALID_DATA_FORMAT int = 0x0400000D   // 数据格式错误
const GM_SYSTEM_FAILURE int = 0x0400000E        // 系统内部错误

const SM2_DEFAULT_ID = "1234567812345678"

const GM_SETSUBJ_2DER_ERROR int = 0x0400000F        // 生成Subject部分失败
const GM_NTP_CONNECT_ERROR int = 0x04000010         // NTP服务器连接失败
const GM_NTP_SYNC_ERROR int = 0x04000011            // NTP服务器同步失败
const GM_CA_IDX_ERROR int = 0x04000012              // CA列表加载失败
const GM_CA_CRL_GET_ERROR int = 0x04000013          // CRL下载失败
const GM_NO_CRL_CHECK int = 0x04000014              // 无CRL验证
const GM_NO_OCSP_CHECK int = 0x04000015             // 无OCSP验证
const GM_VFYSUCC_NOCRLOROCSP int = 0x04000016       // 验签成功 但无证书有效性验证
const GM_CA_NUMS_OUTOF_LIMIT int = 0x04000017       // CA数量超过上限
const GM_APP_NUMS_OUTOF_LIMIT int = 0x04000018      // APP数量超过上限
const GM_UNKNOW_CERT_INFO_TYPE int = 0x04000019     // 未知的证书字段信息
const GM_UNSUPPORT_SIGALT int = 0x0400001A          // 不支持的签名算法
const GM_UNSUPPORT_SIGNATURE_VALUE int = 0x0400001B // 不支持的签名值
const GM_MULTI_OPERATION_ERROR int = 0x0400001C     // 多包运算错误
const GM_MULTI_PACKLENTH_ERROR int = 0x0400001D     // 多包运算长度错误
