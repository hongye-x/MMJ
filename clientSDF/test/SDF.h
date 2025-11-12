#ifndef _SDF_H_
#define _SDF_H_ 1

#ifdef __cplusplus
extern "C"
{
#endif

/*RSA最大模长定义*/
#define SGD_RSA_MAX_BITS 4096

	// /*数据类型定义*/
	// typedef char SGD_CHAR;
	// typedef char SGD_INT8;
	// typedef short SGD_INT16;
	// typedef int SGD_INT32;
	// typedef long long SGD_INT64;
	// typedef unsigned char SGD_UINT8;
	// typedef unsigned short SGD_UINT16;
	// typedef unsigned long long SGD_UINT64;
	// typedef unsigned int int;
	// typedef void *SGD_OBJ;
	// typedef int SGD_BOOL;

	/*设备信息*/
	typedef struct DeviceInfo_st
	{
		unsigned char IssuerName[40];
		unsigned char DeviceName[16];
		unsigned char DeviceSerial[16];
		unsigned int DeviceVersion;
		unsigned int StandardVersion;
		unsigned int AsymAlgAbility[2];
		unsigned int SymAlgAbility;
		unsigned int HashAlgAbility;
		unsigned int BufferSize;
	} DEVICEINFO;

/*RSA密钥*/
#define LiteRSAref_MAX_BITS 4096 // 请勿修改该值
#define LiteRSAref_MAX_LEN ((LiteRSAref_MAX_BITS + 7) / 8)
#define LiteRSAref_MAX_PBITS ((LiteRSAref_MAX_BITS + 1) / 2)
#define LiteRSAref_MAX_PLEN ((LiteRSAref_MAX_PBITS + 7) / 8)

	typedef struct RSArefPublicKeyLite_st
	{
		unsigned int bits;
		unsigned char m[LiteRSAref_MAX_LEN];
		unsigned char e[LiteRSAref_MAX_LEN];
	} RSArefPublicKeyLite;

	typedef struct RSArefPrivateKeyLite_st
	{
		unsigned int bits;
		unsigned char m[LiteRSAref_MAX_LEN];
		unsigned char e[LiteRSAref_MAX_LEN];
		unsigned char d[LiteRSAref_MAX_LEN];
		unsigned char prime[2][LiteRSAref_MAX_PLEN];
		unsigned char pexp[2][LiteRSAref_MAX_PLEN];
		unsigned char coef[LiteRSAref_MAX_PLEN];
	} RSArefPrivateKeyLite;

#define ExRSAref_MAX_BITS 4096
#define ExRSAref_MAX_LEN ((ExRSAref_MAX_BITS + 7) / 8)
#define ExRSAref_MAX_PBITS ((ExRSAref_MAX_BITS + 1) / 2)
#define ExRSAref_MAX_PLEN ((ExRSAref_MAX_PBITS + 7) / 8)

	typedef struct RSArefPublicKeyEx_st
	{
		unsigned int bits;
		unsigned char m[ExRSAref_MAX_LEN];
		unsigned char e[ExRSAref_MAX_LEN];
	} RSArefPublicKeyEx;

	typedef struct RSArefPrivateKeyEx_st
	{
		unsigned int bits;
		unsigned char m[ExRSAref_MAX_LEN];
		unsigned char e[ExRSAref_MAX_LEN];
		unsigned char d[ExRSAref_MAX_LEN];
		unsigned char prime[2][ExRSAref_MAX_PLEN];
		unsigned char pexp[2][ExRSAref_MAX_PLEN];
		unsigned char coef[ExRSAref_MAX_PLEN];
	} RSArefPrivateKeyEx;

// #if defined(SGD_RSA_MAX_BITS) && (SGD_RSA_MAX_BITS > LiteRSAref_MAX_BITS)
// #define RSAref_MAX_BITS ExRSAref_MAX_BITS
// #define RSAref_MAX_LEN ExRSAref_MAX_LEN
// #define RSAref_MAX_PBITS ExRSAref_MAX_PBITS
// #define RSAref_MAX_PLEN ExRSAref_MAX_PLEN

// 	typedef struct RSArefPublicKeyEx_st RSArefPublicKey;
// 	typedef struct RSArefPrivateKeyEx_st RSArefPrivateKey;
// #else
#define RSAref_MAX_BITS LiteRSAref_MAX_BITS
#define RSAref_MAX_LEN LiteRSAref_MAX_LEN
#define RSAref_MAX_PBITS LiteRSAref_MAX_PBITS
#define RSAref_MAX_PLEN LiteRSAref_MAX_PLEN

	typedef struct RSArefPublicKeyLite_st RSArefPublicKey;
	typedef struct RSArefPrivateKeyLite_st RSArefPrivateKey;
	// #endif

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
#define ECCref_MAX_CIPHER_LEN 136

	typedef struct ECCrefPublicKey_st
	{
		unsigned int bits;
		unsigned char x[ECCref_MAX_LEN];
		unsigned char y[ECCref_MAX_LEN];
	} ECCrefPublicKey;

	typedef struct ECCrefPrivateKey_st
	{
		unsigned int bits;
		unsigned char K[ECCref_MAX_LEN];
	} ECCrefPrivateKey;

	typedef struct ECCCipher_st
	{
		unsigned char x[ECCref_MAX_LEN];
		unsigned char y[ECCref_MAX_LEN];
		unsigned char M[32];
		unsigned int L;
		unsigned char C[ECCref_MAX_CIPHER_LEN];
	} ECCCipher;

	typedef struct ECCSignature_st
	{
		unsigned char r[ECCref_MAX_LEN];
		unsigned char s[ECCref_MAX_LEN];
	} ECCSignature;

/*常量定义*/
#define SGD_TRUE 0x00000001
#define SGD_FALSE 0x00000000

/*算法标识*/
#define SGD_SM1_ECB 0x00000101
#define SGD_SM1_CBC 0x00000102
#define SGD_SM1_CFB 0x00000104
#define SGD_SM1_OFB 0x00000108
#define SGD_SM1_MAC 0x00000110
#define SGD_SM1_CTR 0x00000120

#define SGD_SSF33_ECB 0x00000201
#define SGD_SSF33_CBC 0x00000202
#define SGD_SSF33_CFB 0x00000204
#define SGD_SSF33_OFB 0x00000208
#define SGD_SSF33_MAC 0x00000210
#define SGD_SSF33_CTR 0x00000220

#define SGD_SMS4_ECB 0x00000401
#define SGD_SMS4_CBC 0x00000402
#define SGD_SMS4_CFB 0x00000404
#define SGD_SMS4_OFB 0x00000408
#define SGD_SMS4_MAC 0x00000410
#define SGD_SMS4_CTR 0x00000420

#define SGD_3DES_ECB 0x00000801
#define SGD_3DES_CBC 0x00000802
#define SGD_3DES_CFB 0x00000804
#define SGD_3DES_OFB 0x00000808
#define SGD_3DES_MAC 0x00000810
#define SGD_3DES_CTR 0x00000820

#define SGD_AES_ECB 0x00002001
#define SGD_AES_CBC 0x00002002
#define SGD_AES_CFB 0x00002004
#define SGD_AES_OFB 0x00002008
#define SGD_AES_MAC 0x00002010
#define SGD_AES_CTR 0x00002020

#define SGD_RSA 0x00010000
#define SGD_RSA_SIGN 0x00010100
#define SGD_RSA_ENC 0x00010200

#define SGD_SM2 0x00020100
#define SGD_SM2_1 0x00020200
#define SGD_SM2_2 0x00020400
#define SGD_SM2_3 0x00020800

#define SGD_SM9 0x00100000
#define SGD_SM9_1 0x00100100
#define SGD_SM9_2 0x00100200
#define SGD_SM9_3 0x00100400
#define SGD_SM9_4 0x00100800

#define SGD_SM3 0x00000001
#define SGD_SHA1 0x00000002
#define SGD_SHA256 0x00000004
#define SGD_SHA512 0x00000008
#define SGD_SHA384 0x00000010
#define SGD_SHA224 0x00000020
#define SGD_MD5 0x00000080

#define SDR_OK 0x0
#define SDR_BASE 0x01000000
#define SDR_UNKNOWERR (SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT (SDR_BASE + 0x00000002)
#define SDR_COMMFAIL (SDR_BASE + 0x00000003)
#define SDR_HARDFAIL (SDR_BASE + 0x00000004)
#define SDR_OPENDEVICE (SDR_BASE + 0x00000005)
#define SDR_OPENSESSION (SDR_BASE + 0x00000006)
#define SDR_PARDENY (SDR_BASE + 0x00000007)
#define SDR_KEYNOTEXIST (SDR_BASE + 0x00000008)
#define SDR_ALGNOTSUPPORT (SDR_BASE + 0x00000009)
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A)
#define SDR_PKOPERR (SDR_BASE + 0x0000000B)
#define SDR_SKOPERR (SDR_BASE + 0x0000000C)
#define SDR_SIGNERR (SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR (SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR (SDR_BASE + 0x0000000F)
#define SDR_STEPERR (SDR_BASE + 0x00000010)
#define SDR_FILESIZEERR (SDR_BASE + 0x00000011)
#define SDR_FILENOEXIST (SDR_BASE + 0x00000012)
#define SDR_FILEOFSERR (SDR_BASE + 0x00000013)
#define SDR_KEYTYPEERR (SDR_BASE + 0x00000014)
#define SDR_KEYERR (SDR_BASE + 0x00000015)

#define CONNECTION_LIMIT 0x01000101
	// #define SWR_BASE (SDR_BASE + 0x00010000)
	// #define SWR_INVALID_USER (SWR_BASE + 0x00000001)
	// #define SWR_INVALID_AUTHENCODE (SWR_BASE + 0x00000002)
	// #define SWR_PROTOCOL_VER_ERR (SWR_BASE + 0x00000003)
	// #define SWR_INVALID_COMMAND (SWR_BASE + 0x00000004)
	// #define SWR_INVALID_PACKAGE (SWR_BASE + 0x00000005)
	// #define SWR_INVALID_PARAMETERS (SWR_BASE + 0x00000005)
	// #define SWR_FILE_ALREADY_EXIST (SWR_BASE + 0x00000006)
	// #define SWR_SOCKET_ERR_BASE (SWR_BASE + 0x00000100)
	// #define SWR_SOCKET_TIMEOUT (SWR_BASE + 0x00000100)
	// #define SWR_CONNECT_ERR (SWR_BASE + 0x00000101)
	// #define SWR_SET_SOCKOPT_ERR (SWR_BASE + 0x00000102)
	// #define SWR_SOCKET_SEND_ERR (SWR_BASE + 0x00000104)
	// #define SWR_SOCKET_RECV_ERR (SWR_BASE + 0x00000105)
	// #define SWR_SOCKET_RECV_0 (SWR_BASE + 0x00000106)
	// #define SWR_NO_AVAILABLE_HSM (SWR_BASE + 0x00000201)
	// #define SWR_NO_AVAILABLE_CSM (SWR_BASE + 0x00000202)
	// #define SWR_CONFIG_ERR (SWR_BASE + 0x00000301)
	// #define SWR_CARD_BASE (SDR_BASE + 0x00020000)
	// #define SDR_BUFFER_TOO_SMALL (SWR_CARD_BASE + 0x00000101)
	// #define SDR_DATA_PAD (SWR_CARD_BASE + 0x00000102)
	// #define SDR_DATA_SIZE (SWR_CARD_BASE + 0x00000103)
	// #define SDR_CRYPTO_NOT_INIT (SWR_CARD_BASE + 0x00000104)
	// #define SWR_MANAGEMENT_DENY (SWR_CARD_BASE + 0x00001001)
	// #define SWR_OPERATION_DENY (SWR_CARD_BASE + 0x00001002)
	// #define SWR_DEVICE_STATUS_ERR (SWR_CARD_BASE + 0x00001003)
	// #define SWR_LOGIN_ERR 1(SWR_CARD_BASE + 0x00001011)
	// #define SWR_USERID_ERR (SWR_CARD_BASE + 0x00001012)
	// #define SWR_PARAMENT_ERR (SWR_CARD_BASE + 0x00001013)
	// #define SWR_KEYTYPEERR (SWR_CARD_BASE + 0x00000020)

	// 设备管理类函数
	// 1. 打开设备
	int SDF_OpenDevice(void **phDeviceHandle);
	// 2. 关闭设备
	int SDF_CloseDevice(void *hDeviceHandle);
	// 3. 创建会话
	int SDF_OpenSession(void *hDeviceHandle, void **psesh);
	// 4. 关闭会话
	int SDF_CloseSession(void *sesh);
	// 5. 获取设备信息
	int SDF_GetDeviceInfo(void *sesh, DEVICEINFO *pstDeviceInfo);
	// 6. 产生随机数
	int SDF_GenerateRandom(void *sesh, unsigned int uiLength, unsigned char *pucRandom);
	// 7. 获取私钥使用权限
	int SDF_GetPrivateKeyAccessRight(void *sesh, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength);
	// 8. 释放私钥使用权限
	int SDF_ReleasePrivateKeyAccessRight(void *sesh, unsigned int uiKeyIndex);

	// 密钥管理类函数
	// 9. 导出ＲＳＡ签名公钥
	int SDF_ExportSignPublicKey_RSA(void *sesh, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
	// 10. 导出ＲＳＡ加密公钥
	int SDF_ExportEncPublicKey_RSA(void *sesh, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
	// 11. 产生ＲＳＡ非对称密钥对并输出
	int SDF_GenerateKeyPair_RSA(void *sesh, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey); // ok
	// 12. 生成会话密钥并用内部ＲＳＡ公钥加密输出
	int SDF_GenerateKeyWithIPK_RSA(void *sesh, unsigned int uiIPKIndex, unsigned int uiKeyBits, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
	// 13. 生成会话密钥并用外部ＲＳＡ公钥加密输出
	int SDF_GenerateKeyWithEPK_RSA(void *sesh, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
	// 14. 导入会话密钥并用内部ＲＳＡ私钥解密
	int SDF_ImportKeyWithISK_RSA(void *sesh, unsigned int uiISKIndex,
								 unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
	// 15. 基于ＲＳＡ算法的数字信封转换
	int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *sesh, unsigned int uiKeyIndex,
										   RSArefPublicKey *pucPublicKey, unsigned char *pucDEInput,
										   unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *puiDELength);
	// 16. 导出ＥＣＣ签名公钥
	int SDF_ExportSignPublicKey_ECC(void *sesh, unsigned int uiKeyIndex,
									ECCrefPublicKey *pucPublicKey);
	// 17. 导出ＥＣＣ加密公钥
	int SDF_ExportEncPublicKey_ECC(void *sesh, unsigned int uiKeyIndex,
								   ECCrefPublicKey *pucPublicKey);
	// 18. 产生ＥＣＣ非对称密钥对并输出
	int SDF_GenerateKeyPair_ECC(void *sesh, unsigned int uiAlgID,
								unsigned int uiKeyBits,
								ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
	// 19. 生成会话密钥并用内部ＥＣＣ公钥加密输出
	int SDF_GenerateKeyWithIPK_ECC(void *sesh, unsigned int uiIPKIndex,
								   unsigned int uiKeyBits,
								   ECCCipher *pucKey, void **phKeyHandle);
	// 20. 生成会话密钥并用外部ＥＣＣ公钥加密输出
	int SDF_GenerateKeyWithEPK_ECC(void *sesh, unsigned int uiKeyBits,
								   unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
								   ECCCipher *pucKey, void **phKeyHandle);
	// 21. 导入会话密钥并用内部ＥＣＣ私钥解密
	int SDF_ImportKeyWithISK_ECC(void *sesh, unsigned int uiISKIndex,
								 ECCCipher *pucKey, void **phKeyHandle);
	// 22. 生成密钥协商参数并输出
	int SDF_GenerateAgreementDataWithECC(void *sesh,
										 unsigned int uiISKIndex, unsigned int uiKeyBits,
										 unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
										 ECCrefPublicKey *pucSponsorPublicKey,
										 ECCrefPublicKey *pucSponsorTmpPublicKey,
										 void **phAgreementHandle);
	// 23. 计算会话密钥
	int SDF_GenerateKeyWithECC(void *sesh,
							   unsigned char *pucResponseID, unsigned int uiResponseIDLength,
							   ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey,
							   void *hAgreementHandle, void **phKeyHandle);
	// 24. 产生协商数据并计算会话密钥
	int SDF_GenerateAgreementDataAndKeyWithECC(void *sesh, unsigned int uiISKIndex,
											   unsigned int uiKeyBits, unsigned char *pucResponseID,
											   unsigned int uiResponseIDLength,
											   unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
											   ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
											   ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey,
											   void **phKeyHandle);
	// 25. 基于 ＥＣＣ算法的数字信封转换
	int SDF_ExchangeDigitEnvelopeBaseOnECC(void *sesh,
										   unsigned int uiKeyIndex, unsigned int uiAlgID,
										   ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
										   ECCCipher *pucEncDataOut);
	// 26. 生成会话密钥并用密钥加密密钥加密输出
	int SDF_GenerateKeyWithKEK(void *sesh,
							   unsigned int uiKeyBits, unsigned int uiAlgID,
							   unsigned int uiKEKIndex, unsigned char *pucKey,
							   unsigned int *puiKeyLength, void **phKeyHandle);
	// 27. 导入会话密钥并用密钥加密密钥解密
	int SDF_ImportKeyWithKEK(void *sesh,
							 unsigned int uiAlgID, unsigned int uiKEKIndex,
							 unsigned char *pucKey, unsigned int uiKeyLength,
							 void **phKeyHandle);
	// 28. 导入明文会话密钥
	int SDF_ImportKey(void *sesh,
					  unsigned char *pucKey, unsigned int uiKeyLength,
					  void **phKeyHandle);
	// 29. 销毁会话密钥
	int SDF_DestroyKey(void *sesh, void *hKeyHandle);

	// 非对称算法运算类函数
	// 30. 外部公钥ＲＳＡ运算
	int SDF_ExternalPublicKeyOperation_RSA(void *sesh,
										   RSArefPublicKey *pucPublicKey,
										   unsigned char *pucDataInput, unsigned int uiInputLength,
										   unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	// 31. 外部私钥ＲＳＡ运算
	int SDF_ExternalPrivateKeyOperation_RSA(void *sesh,
											RSArefPrivateKey *pucPrivateKey,
											unsigned char *pucDataInput, unsigned int uiInputLength,
											unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	// 32. 内部公钥ＲＳＡ运算
	int SDF_InternalPublicKeyOperation_RSA(void *sesh,
										   unsigned int uiKeyIndex,
										   unsigned char *pucDataInput, unsigned int uiInputLength,
										   unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	// 33. 内部私ＲＳＡ运算
	int SDF_InternalPrivateKeyOperation_RSA(void *sesh,
											unsigned int uiKeyIndex,
											unsigned char *pucDataInput, unsigned int uiInputLength,
											unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	// 34. 外部密钥ＥＣＣ签名
	int SDF_ExternalSign_ECC(void *sesh,
							 unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
							 unsigned char *pucData, unsigned int uiDataLength,
							 ECCSignature *pucSignature);
	// 35. 外部密钥ＥＣＣ验证
	int SDF_ExternalVerify_ECC(void *sesh,
							   unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
							   unsigned char *pucDataInput, unsigned int uiInputLength,
							   ECCSignature *pucSignature);
	// 36. 内部密钥ＥＣＣ签名
	int SDF_InternalSign_ECC(void *sesh,
							 unsigned int uiISKIndex, unsigned char *pucData,
							 unsigned int uiDataLength, ECCSignature *pucSignature);
	// 37. 内部密钥ＥＣＣ验证
	int SDF_InternalVerify_ECC(void *sesh,
							   unsigned int uiISKIndex, unsigned char *pucData,
							   unsigned int uiDataLength, ECCSignature *pucSignature);
	// 38. 外部密钥ＥＣＣ加密
	int SDF_ExternalEncrypt_ECC(void *sesh,
								unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
								unsigned char *pucData, unsigned int uiDataLength,
								ECCCipher *pucEncData);
	// 39. 外部密钥ＥＣＣ解密
	int SDF_ExternalDecrypt_ECC(void *sesh,
								unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
								ECCCipher *pucEncData,
								unsigned char *pucData, unsigned int *puiDataLength);

	// 对称算法运算类函数
	// 40. 对称加密
	int SDF_Encrypt(void *sesh,
					void *hKeyHandle, unsigned int uiAlgID,
					unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength,
					unsigned char *pucEncData, unsigned int *puiEncDataLength);
	// 41. 对称解密
	int SDF_Decrypt(void *sesh,
					void *hKeyHandle, unsigned int uiAlgID,
					unsigned char *pucIV, unsigned char *pucEncData, unsigned int uiEncDataLength,
					unsigned char *pucData, unsigned int *puiDataLength);
	// 42. 计算ＭＡＣ
	int SDF_CalculateMAC(void *sesh,
						 void *hKeyHandle, unsigned int uiAlgID,
						 unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength,
						 unsigned char *pucMAC, unsigned int *puiMACLength);

	// 杂凑运算类函数
	// 43. 杂凑运算初始化
	int SDF_HashInit(void *sesh,
					 unsigned int uiAlgID,
					 ECCrefPublicKey *pucPublicKey, unsigned char *pucID, unsigned int uiIDLength);
	// 44. 多包杂凑运算
	int SDF_HashUpdate(void *sesh,
					   unsigned char *pucData, unsigned int uiDataLength);
	// 45. 杂凑运算结束
	int SDF_HashFinal(void *sesh,
					  unsigned char *pucHash, unsigned int *puiHashLength);

	// 用户文件操作类函数
	// 46. 创建文件
	int SDF_CreateFile(void *sesh,
					   unsigned char *pucFileName, unsigned int uiNameLen,
					   unsigned int uiFileSize);
	// 47. 读取文件
	int SDF_ReadFile(void *sesh,
					 unsigned char *pucFileName, unsigned int uiNameLen,
					 unsigned int uiOffset,
					 unsigned int *puiReadLength, unsigned char *pucBuffer);
	// 48. 写文件
	int SDF_WriteFile(void *sesh,
					  unsigned char *pucFileName, unsigned int uiNameLen,
					  unsigned int uiOffset,
					  unsigned int uiWriteLength, unsigned char *pucBuffer);
	// 49. 删除文件
	int SDF_DeleteFile(void *sesh,
					   unsigned char *pucFileName, unsigned int uiNameLen);

#ifdef __cplusplus
}
#endif

#endif