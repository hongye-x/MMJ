package keymanage

import (
	"encoding/base64"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"sig_vfy/src/sqlop"
	"unsafe"

	"gorm.io/gorm"
)

// 最大对称密钥存储数量
const MAX_SYM_KEY_NUM int = 1024

// 最大RSA密钥存储数量
const MAX_RSA_KEY_NUM int = 16 * 2

// 最大SM2密钥存储数量
const MAX_SM2_KEY_NUM int = 128 * 2

const SYM_TYPE_FLAG int = 0
const RSA_TYPE_FLAG int = 1
const SM2_TYPE_FLAG int = 2

/** 内部存储对称密钥类型 **/
type MemStorSymKey struct {
	Idx      int
	KeyBits  int
	KeyValue []byte
}

/** 内部存储SM2密钥类型 **/
type MemStorSM2Key struct {
	Idx         int
	PrivKeyAuth int      // 是否有密钥授权码
	PrivPin     [32]byte // 密钥授权验证码

	PubKey  ISDF.ECCrefPublicKey
	PrivKey ISDF.ECCrefPrivateKey
}

/** 内部存储RSA密钥类型 **/
type MemStorRSAKey struct {
	Idx         int
	PrivKeyAuth int      // 是否有密钥授权码
	PrivPin     [32]byte // 密钥授权验证码

	PubKey  ISDF.RSArefPublicKey
	PrivKey ISDF.RSArefPrivateKey
}

var MemSymMap = make(map[int]*MemStorSymKey, MAX_SYM_KEY_NUM)
var MemSM2Map = make(map[int]*MemStorSM2Key, MAX_SM2_KEY_NUM)
var MemRSAMap = make(map[int]*MemStorRSAKey, MAX_RSA_KEY_NUM)

func checkKeyExistInSql(keyIdx int, keyType int) (int, *b.StdErr) {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return 0, err
		}
	}

	var count int64
	var errno = b.SQL_SELECT_ERROR
	var keyTable any
	if keyType == SYM_TYPE_FLAG {
		keyTable = &sqlop.SymKey{}
	} else if keyType == RSA_TYPE_FLAG {
		keyTable = &sqlop.RsaKey{}
	} else if keyType == SM2_TYPE_FLAG {
		keyTable = &sqlop.EccKey{}
	} else {
		return errno, b.CreateStdErr(errno,
			"Query Key Type Error Type : %d", keyType)
	}

	err := sqlop.Gsqlh.Model(keyTable).
		Where("key_idx = ?", keyIdx).Count(&count).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return 0, b.CreateStdErr(errno, "%v", err)
	}

	return int(count), nil
}

func AddKey2SQL(sesh unsafe.Pointer, keyValue any, rootKey []byte) *b.StdErr {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return err
		}
	}

	var keyType int
	var keyIdx int
	switch k := keyValue.(type) {
	case MemStorSymKey:
		keyType = SYM_TYPE_FLAG
		keyIdx = k.Idx
	case *MemStorSymKey:
		keyType = SYM_TYPE_FLAG
		keyIdx = k.Idx
	case MemStorSM2Key:
		keyType = SM2_TYPE_FLAG
		keyIdx = k.Idx
	case *MemStorSM2Key:
		keyType = SM2_TYPE_FLAG
		keyIdx = k.Idx
	case MemStorRSAKey:
		keyType = RSA_TYPE_FLAG
		keyIdx = k.Idx
	case *MemStorRSAKey:
		keyType = RSA_TYPE_FLAG
		keyIdx = k.Idx
	default:
		return b.CreateStdErr(b.KEY_TYPE_ERROR,
			"Stor Key Type Error")
	}
	ifexist, stderr := checkKeyExistInSql(keyIdx, keyType)
	if stderr != nil {
		return stderr
	}
	if ifexist != 0 {
		return b.CreateStdErr(b.STORKEY_INTERNAL_EXIST,
			"StorKey Internal Has Exist Idx : %d", keyIdx)
	}

	switch k := keyValue.(type) {
	case MemStorSymKey:
		keyBinaryDigest, uiret :=
			ISDF.Hash(sesh, k.KeyValue)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		edKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, k.KeyValue)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		// keyBytes := k.KeyBits / 8
		keyB64Value := base64.StdEncoding.EncodeToString(edKeyValue)
		keyB64Digest := base64.StdEncoding.EncodeToString(keyBinaryDigest)
		// add to sql
		err := sqlop.Gsqlh.Create(&sqlop.SymKey{KeyIdx: k.Idx, KeyBits: k.KeyBits,
			KeyValue: []byte(keyB64Value), KeyDigest: []byte(keyB64Digest)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v",
				err)
		}

	case *MemStorSymKey:
		keyBinaryDigest, uiret :=
			ISDF.Hash(sesh, k.KeyValue)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		edKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, k.KeyValue)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		// keyBytes := k.KeyBits / 8
		keyB64Value := base64.StdEncoding.EncodeToString(edKeyValue)
		keyB64Digest := base64.StdEncoding.EncodeToString(keyBinaryDigest)
		// add to sql
		err := sqlop.Gsqlh.Create(&sqlop.SymKey{KeyIdx: k.Idx, KeyBits: k.KeyBits,
			KeyValue: []byte(keyB64Value), KeyDigest: []byte(keyB64Digest)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v",
				err)
		}

	case MemStorSM2Key:
		sm2pubkBinary := b.ConcatSlices(k.PubKey.X[:], k.PubKey.Y[:])
		sm2kBinary := b.ConcatSlices(sm2pubkBinary, k.PrivKey.K[:])
		keyBinaryDigest, uiret :=
			ISDF.Hash(sesh, sm2kBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		edPubKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, sm2pubkBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		edPivKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, k.PrivKey.K[:])
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		var pivKeyB64Auth string
		if k.PrivKeyAuth != 0 {
			pivKeyB64Auth = base64.StdEncoding.EncodeToString(k.PrivPin[:])
		}
		pubKeyB64Value := base64.StdEncoding.EncodeToString(edPubKeyValue)
		pivKeyB64Value := base64.StdEncoding.EncodeToString(edPivKeyValue)
		keyB64Digest := base64.StdEncoding.EncodeToString(keyBinaryDigest)

		err := sqlop.Gsqlh.Create(&sqlop.EccKey{KeyIdx: k.Idx, KeyBits: int(k.PubKey.Bits), PrivKeyAuth: k.PrivKeyAuth,
			PrivKeyAuthCode: []byte(pivKeyB64Auth), PubKeyValue: []byte(pubKeyB64Value),
			PivKeyValue: []byte(pivKeyB64Value), KeyDigest: []byte(keyB64Digest)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v",
				err)
		}

	case *MemStorSM2Key:
		sm2pubkBinary := b.ConcatSlices(k.PubKey.X[:], k.PubKey.Y[:])
		sm2kBinary := b.ConcatSlices(sm2pubkBinary, k.PrivKey.K[:])
		keyBinaryDigest, uiret :=
			ISDF.Hash(sesh, sm2kBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		edPubKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, sm2pubkBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		edPivKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, k.PrivKey.K[:])
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		var pivKeyB64Auth string
		if k.PrivKeyAuth != 0 {
			pivKeyB64Auth = base64.StdEncoding.EncodeToString(k.PrivPin[:])
		}
		pubKeyB64Value := base64.StdEncoding.EncodeToString(edPubKeyValue)
		pivKeyB64Value := base64.StdEncoding.EncodeToString(edPivKeyValue)
		keyB64Digest := base64.StdEncoding.EncodeToString(keyBinaryDigest)

		err := sqlop.Gsqlh.Create(&sqlop.EccKey{KeyIdx: k.Idx, KeyBits: int(k.PubKey.Bits), PrivKeyAuth: k.PrivKeyAuth,
			PrivKeyAuthCode: []byte(pivKeyB64Auth), PubKeyValue: []byte(pubKeyB64Value),
			PivKeyValue: []byte(pivKeyB64Value), KeyDigest: []byte(keyB64Digest)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v",
				err)
		}

	case MemStorRSAKey:
		rsapubkBinary := b.ConcatSlices(k.PubKey.M[:], k.PubKey.E[:])
		rsapivkBinary := b.ConcatSlices(k.PrivKey.M[:], k.PrivKey.E[:], k.PrivKey.D[:],
			k.PrivKey.Prime[0][:], k.PrivKey.Prime[1][:], k.PrivKey.Pexp[0][:], k.PrivKey.Pexp[1][:], k.PrivKey.Coef[:])
		rsakBinary := b.ConcatSlices(rsapubkBinary, rsapivkBinary)
		keyBinaryDigest, uiret :=
			ISDF.Hash(sesh, rsakBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		edPubKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, rsapubkBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		edPivKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, rsapivkBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		var pivKeyB64Auth string
		if k.PrivKeyAuth != 0 {
			pivKeyB64Auth = base64.StdEncoding.EncodeToString(k.PrivPin[:])
		}
		pubKeyB64Value := base64.StdEncoding.EncodeToString(edPubKeyValue)
		pivKeyB64Value := base64.StdEncoding.EncodeToString(edPivKeyValue)
		keyB64Digest := base64.StdEncoding.EncodeToString(keyBinaryDigest)

		err := sqlop.Gsqlh.Create(&sqlop.RsaKey{KeyIdx: k.Idx, KeyBits: int(k.PubKey.Bits), PrivKeyAuth: k.PrivKeyAuth,
			PrivKeyAuthCode: []byte(pivKeyB64Auth), PubKeyValue: []byte(pubKeyB64Value),
			PivKeyValue: []byte(pivKeyB64Value), KeyDigest: []byte(keyB64Digest)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v",
				err)
		}

	case *MemStorRSAKey:
		rsapubkBinary := b.ConcatSlices(k.PubKey.M[:], k.PubKey.E[:])
		rsapivkBinary := b.ConcatSlices(k.PrivKey.M[:], k.PrivKey.E[:], k.PrivKey.D[:],
			k.PrivKey.Prime[0][:], k.PrivKey.Prime[1][:], k.PrivKey.Pexp[0][:], k.PrivKey.Pexp[1][:], k.PrivKey.Coef[:])
		rsakBinary := b.ConcatSlices(rsapubkBinary, rsapivkBinary)
		keyBinaryDigest, uiret :=
			ISDF.Hash(sesh, rsakBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		edPubKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, rsapubkBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}
		edPivKeyValue, uiret := ISDF.EncryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, rsapivkBinary)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Stor Key SDF Func Error")
		}

		var pivKeyB64Auth string
		if k.PrivKeyAuth != 0 {
			pivKeyB64Auth = base64.StdEncoding.EncodeToString(k.PrivPin[:])
		}
		pubKeyB64Value := base64.StdEncoding.EncodeToString(edPubKeyValue)
		pivKeyB64Value := base64.StdEncoding.EncodeToString(edPivKeyValue)
		keyB64Digest := base64.StdEncoding.EncodeToString(keyBinaryDigest)

		err := sqlop.Gsqlh.Create(&sqlop.RsaKey{KeyIdx: k.Idx, KeyBits: int(k.PubKey.Bits), PrivKeyAuth: k.PrivKeyAuth,
			PrivKeyAuthCode: []byte(pivKeyB64Auth), PubKeyValue: []byte(pubKeyB64Value),
			PivKeyValue: []byte(pivKeyB64Value), KeyDigest: []byte(keyB64Digest)}).Error
		if err != nil {
			return b.CreateStdErr(b.SQL_INSERT_ERROR, "%v",
				err)
		}
	}
	return nil
}

func AddKey2Map(keyValue any) {
	switch k := keyValue.(type) {
	case MemStorSymKey:
		MemSymMap[k.Idx] = &k
	case *MemStorSymKey:
		MemSymMap[k.Idx] = k
	case MemStorSM2Key:
		MemSM2Map[k.Idx] = &k
	case *MemStorSM2Key:
		MemSM2Map[k.Idx] = k
	case MemStorRSAKey:
		MemRSAMap[k.Idx] = &k
	case *MemStorRSAKey:
		MemRSAMap[k.Idx] = k
	}
}

func DelKeyFromSQL(keyIdx int, keyType int) *b.StdErr {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return err
		}
	}

	var keyTable any
	if keyType == SYM_TYPE_FLAG {
		keyTable = &sqlop.SymKey{}
	} else if keyType == RSA_TYPE_FLAG {
		keyTable = &sqlop.RsaKey{}
	} else if keyType == SM2_TYPE_FLAG {
		keyTable = &sqlop.EccKey{}
	} else {
		return b.CreateStdErr(b.KEY_TYPE_ERROR,
			"Del Key Type Error Type : %d", keyType)
	}

	sqlop.Gsqlh.Model(keyTable).Delete(keyTable, keyIdx)
	return nil
}

func DelKeyFromMap(keyIdx int, keyType int) *b.StdErr {
	if keyType == SYM_TYPE_FLAG {
		MemSymMap[keyIdx] = nil
	} else if keyType == RSA_TYPE_FLAG {
		MemRSAMap[keyIdx] = nil
	} else if keyType == SM2_TYPE_FLAG {
		MemSM2Map[keyIdx] = nil
	} else {
		return b.CreateStdErr(b.KEY_TYPE_ERROR,
			"Del Key Type Error Type : %d", keyType)
	}
	return nil
}

func GetKeyValueFromSQL(sesh unsafe.Pointer, idx int, keyType int, rootKey []byte) (any, []byte, *b.StdErr) {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return nil, nil, err
		}
	}

	if keyType == SYM_TYPE_FLAG {
		var sqlKeyValue sqlop.SymKey
		var keyValue MemStorSymKey
		err := sqlop.Gsqlh.First(&sqlKeyValue, idx).Error
		if err != nil {
			return nil, nil,
				b.CreateStdErr(b.KEY_INSQL_NOEXIST,
					"Get Key Vaule Error")
		} else {
			keyValue.Idx = sqlKeyValue.KeyIdx
			keyValue.KeyBits = sqlKeyValue.KeyBits
			edKeyValue, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.KeyValue))
			pKeyV, uiret := ISDF.DecryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, edKeyValue)
			if uiret != 0 {
				return nil, nil,
					b.CreateStdErr(uiret,
						"Get Key Vaule Error")
			}
			keyValue.KeyValue = pKeyV
			digest, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.KeyDigest))
			return &keyValue, digest, nil
		}
	} else if keyType == SM2_TYPE_FLAG {
		var sqlKeyValue sqlop.EccKey
		var keyValue MemStorSM2Key
		err := sqlop.Gsqlh.First(&sqlKeyValue, idx).Error
		if err != nil {
			return nil, nil,
				b.CreateStdErr(b.KEY_INSQL_NOEXIST,
					"Get Key Vaule Error")
		} else {
			keyBytes := ISDF.ECCref_MAX_LEN
			keyValue.Idx = sqlKeyValue.KeyIdx
			keyValue.PrivKeyAuth = sqlKeyValue.PrivKeyAuth
			if keyValue.PrivKeyAuth == 1 {
				tmpPivPin, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.PrivKeyAuthCode))
				keyValue.PrivPin = [32]byte(tmpPivPin[:32])
			}
			edbPubKey, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.PubKeyValue))
			edbPivKey, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.PivKeyValue))
			pPubKey, uiret := ISDF.DecryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, edbPubKey)
			if uiret != 0 {
				return nil, nil,
					b.CreateStdErr(uiret,
						"Get Key Vaule Error")
			}
			pPivKey, uiret := ISDF.DecryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, edbPivKey)
			if uiret != 0 {
				return nil, nil,
					b.CreateStdErr(uiret,
						"Get Key Vaule Error")
			}
			keyValue.PubKey.Bits = uint(sqlKeyValue.KeyBits)
			keyValue.PubKey.X = *(*[ISDF.ECCref_MAX_LEN]byte)((unsafe.Pointer)(&pPubKey[0]))
			keyValue.PubKey.Y = *(*[ISDF.ECCref_MAX_LEN]byte)((unsafe.Pointer)(&pPubKey[keyBytes]))
			keyValue.PrivKey.Bits = uint(sqlKeyValue.KeyBits)
			keyValue.PrivKey.K = *(*[ISDF.ECCref_MAX_LEN]byte)((unsafe.Pointer)(&pPivKey[0]))
			digest, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.KeyDigest))
			return &keyValue, digest, nil
		}
	} else if keyType == RSA_TYPE_FLAG {
		var sqlKeyValue sqlop.RsaKey
		var keyValue MemStorRSAKey
		err := sqlop.Gsqlh.First(&sqlKeyValue, idx).Error
		if err != nil {
			return nil, nil,
				b.CreateStdErr(b.KEY_INSQL_NOEXIST,
					"Get Key Vaule Error")
		} else {
			keyBytes := ISDF.LiteRSAref_MAX_PLEN
			keyValue.Idx = sqlKeyValue.KeyIdx
			keyValue.PrivKeyAuth = sqlKeyValue.PrivKeyAuth
			if keyValue.PrivKeyAuth == 1 {
				tmpPivPin, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.PrivKeyAuthCode))
				keyValue.PrivPin = [32]byte(tmpPivPin[:32])
			}
			edbPubKey, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.PubKeyValue))
			edbPivKey, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.PivKeyValue))
			pPubKey, uiret := ISDF.DecryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, edbPubKey)
			if uiret != 0 {
				return nil, nil,
					b.CreateStdErr(uiret,
						"Get Key Vaule Error")
			}
			pPivKey, uiret := ISDF.DecryptEx(sesh, rootKey, ISDF.SGD_SM4_ECB, nil, edbPivKey)
			if uiret != 0 {
				return nil, nil,
					b.CreateStdErr(uiret,
						"Get Key Vaule Error")
			}
			keyValue.PubKey.Bits = uint(sqlKeyValue.KeyBits)
			keyValue.PubKey.M = *(*[ISDF.LiteRSAref_MAX_LEN]byte)((unsafe.Pointer)(&pPubKey[0]))
			keyValue.PubKey.E = *(*[ISDF.LiteRSAref_MAX_LEN]byte)((unsafe.Pointer)(&pPubKey[keyBytes*2]))
			keyValue.PrivKey.Bits = uint(sqlKeyValue.KeyBits)
			keyValue.PrivKey.M = *(*[ISDF.LiteRSAref_MAX_LEN]byte)((unsafe.Pointer)(&pPivKey[0]))
			keyValue.PrivKey.E = *(*[ISDF.LiteRSAref_MAX_LEN]byte)((unsafe.Pointer)(&pPivKey[keyBytes*2]))
			keyValue.PrivKey.D = *(*[ISDF.LiteRSAref_MAX_LEN]byte)((unsafe.Pointer)(&pPivKey[keyBytes*4]))
			keyValue.PrivKey.Prime[0] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)((unsafe.Pointer)(&pPivKey[keyBytes*6]))
			keyValue.PrivKey.Prime[1] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)((unsafe.Pointer)(&pPivKey[keyBytes*7]))
			keyValue.PrivKey.Pexp[0] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)((unsafe.Pointer)(&pPivKey[keyBytes*8]))
			keyValue.PrivKey.Pexp[1] = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)((unsafe.Pointer)(&pPivKey[keyBytes*9]))
			keyValue.PrivKey.Coef = *(*[ISDF.LiteRSAref_MAX_PLEN]byte)((unsafe.Pointer)(&pPivKey[keyBytes*10]))
			digest, _ := base64.StdEncoding.DecodeString(string(sqlKeyValue.KeyDigest))
			return &keyValue, digest, nil
		}
	} else {
		return nil, nil, b.CreateStdErr(
			b.KEY_TYPE_ERROR, "Get Key Type Error")
	}
}

func GetKeyListFromSQL(keyType int) (
	[]int, *b.StdErr) {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return nil, err
		}
	}

	var idxs []int
	var pivauth []int
	var keyTable any
	if keyType == SYM_TYPE_FLAG {
		keyTable = &sqlop.SymKey{}
	} else if keyType == RSA_TYPE_FLAG {
		keyTable = &sqlop.RsaKey{}
	} else if keyType == SM2_TYPE_FLAG {
		keyTable = &sqlop.EccKey{}
	}

	err := sqlop.Gsqlh.Model(keyTable).Select("key_idx").Pluck("key_idx", &idxs).Error
	if err != nil {
		return nil, b.CreateStdErr(b.SQL_SELECT_ERROR,
			"%v", err)
	}

	if keyType != SYM_TYPE_FLAG {
		err = sqlop.Gsqlh.Model(keyTable).Select("priv_key_auth").Pluck("priv_key_auth", &pivauth).Error
		if err != nil {
			return nil, b.CreateStdErr(b.SQL_SELECT_ERROR,
				"%v", err)
		}

		var i int
		for i = 0; i < len(idxs); i++ {
			if pivauth[i] == 1 {
				idxs[i] |= 0x80000000
			}
		}
	}

	return idxs, nil
}

func SetPivKPinInSQL(sesh unsafe.Pointer, keyIdx int, keyType int, keypin []byte) *b.StdErr {
	var authright int = 0
	var b64auth string
	var err1 *gorm.DB
	var err2 *gorm.DB

	if keypin != nil {
		authright = 1
		dig, uiret := ISDF.Hash(sesh, keypin)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret),
				"Set PivKey Pin SDF Func Error")
		}
		b64auth = base64.StdEncoding.EncodeToString(dig)
	}

	count, err := checkKeyExistInSql(keyIdx, keyType)
	if count == 0 || err != nil {
		return b.CreateStdErr(b.PIV_PIN_SET_ERROR, "%v", err1.Error)
	}

	keyIdx2 := keyIdx + 1
	if keyType == SM2_TYPE_FLAG {
		err1 = sqlop.Gsqlh.Model(&sqlop.EccKey{}).Where("key_idx = ?", keyIdx).
			Updates(&sqlop.EccKey{
				PrivKeyAuth:     authright,
				PrivKeyAuthCode: []byte(b64auth)})
		err2 = sqlop.Gsqlh.Model(&sqlop.EccKey{}).Where("key_idx = ?", keyIdx2).
			Updates(&sqlop.EccKey{
				PrivKeyAuth:     authright,
				PrivKeyAuthCode: []byte(b64auth)})

	} else if keyType == RSA_TYPE_FLAG {
		err1 = sqlop.Gsqlh.Model(&sqlop.RsaKey{}).Where("key_idx = ?", keyIdx).
			Updates(&sqlop.RsaKey{
				PrivKeyAuth:     authright,
				PrivKeyAuthCode: []byte(b64auth)})

		err2 = sqlop.Gsqlh.Model(&sqlop.RsaKey{}).Where("key_idx = ?", keyIdx2).
			Updates(&sqlop.RsaKey{
				PrivKeyAuth:     authright,
				PrivKeyAuthCode: []byte(b64auth)})
	}

	if err1.Error != nil {
		return b.CreateStdErr(b.SQL_SELECT_ERROR, "%v", err1.Error)
	}
	if err2.Error != nil {
		return b.CreateStdErr(b.SQL_SELECT_ERROR, "%v", err2.Error)
	}
	return nil
}

func GetDevInitStatus() int {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return 0
		}
	}

	var record sqlop.IfDevInited
	idxToQuery := 1
	err := sqlop.Gsqlh.First(&record, idxToQuery).Error
	if err != nil {
		return 0
	}
	return record.Ifinit
}

func SqlSetDevInited() *b.StdErr {
	if sqlop.Gsqlh == nil {
		err := sqlop.SqlConnect()
		if err != nil {
			return err
		}
	}

	idxToUpdate := 1
	err := sqlop.Gsqlh.Model(&sqlop.IfDevInited{}).Where("id = ?", idxToUpdate).Update("ifinit", 1).Error
	if err != nil {
		return b.CreateStdErr(b.SQL_CONNECT_ERROR, "%v", err.Error())
	}

	return nil
}
