package initialize

import (
	"bytes"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"unsafe"
)

const ORGINAL_KEY_IDX = 1
const ROOTKEY_LEN = 16
const ROOTKEY_FILENAM = "enc_root_key"
const ROOTKEY_PROTECTKEY_FILENAME = "root_key_proc_key"
const ENCTYPE = ISDF.SGD_SM4_ECB

var PRootKey []byte = nil

func destoryRootKey(sesh unsafe.Pointer) *b.StdErr {
	uiret := ISDF.DeleteFile(sesh, []byte(ROOTKEY_PROTECTKEY_FILENAME))
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "DestoryRootKey SDF Func Error")
	}

	uiret = ISDF.DeleteFile(sesh, []byte(ROOTKEY_FILENAM))
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "DestoryRootKey SDF Func Error")
	}

	uiret = ISDF.DeleteKEKByIdx(sesh, ORGINAL_KEY_IDX)
	if uiret != 0 && uiret != 0x01000008 {
		return b.CreateStdErr(int(uiret), "DestoryRootKey SDF Func Error")
	}

	if PRootKey != nil {
		for i := 0; i < len(PRootKey); i++ {
			PRootKey[i] = 0
		}
	}

	return nil
}

func GenRootKey(sesh unsafe.Pointer) *b.StdErr {
	list, stderr := b.ReadConfigValues("PROKEY_ENCTYPE")
	if stderr != nil {
		return stderr
	}
	protype := list["PROKEY_ENCTYPE"].([]byte)

	err := destoryRootKey(sesh)
	if err != nil {
		return err
	}

	uiret := ISDF.CreateFile(sesh, []byte(ROOTKEY_FILENAM), 128)
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "GenRootKey RootKey Exist")
	}

	uiret = ISDF.CreateFile(sesh, []byte(ROOTKEY_PROTECTKEY_FILENAME), 128)
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "GenRootKey RootKey Exist")
	}

	uiret = ISDF.GenKEK2Idx(sesh, ORGINAL_KEY_IDX, ROOTKEY_LEN)
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
	}
	if bytes.Equal(protype, []byte("ECB")) {
		encProKey, proKeyh, uiret := ISDF.GenerateKeyWithKEK(sesh, ROOTKEY_LEN*8, ENCTYPE, ORGINAL_KEY_IDX)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}
		defer ISDF.DestroyKey(sesh, proKeyh)

		rootKey, uiret := ISDF.GenerateRandom(sesh, ROOTKEY_LEN)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}

		encRootKey, uiret := ISDF.Encrypt(sesh, proKeyh, ENCTYPE, nil, rootKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}

		uiret = ISDF.WriteFile(sesh, []byte(ROOTKEY_FILENAM), 0, encRootKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}

		// CBC encProKeyLen = 48
		// ECB encProKeyLen = 32
		uiret = ISDF.WriteFile(sesh, []byte(ROOTKEY_PROTECTKEY_FILENAME), 0, encProKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}
	} else if bytes.Equal(protype, []byte("CBC")) {
		encProKey, proKeyh, uiret := ISDF.GenerateKeyWithKEK(sesh, ROOTKEY_LEN*8, ISDF.SGD_SM4_CBC, ORGINAL_KEY_IDX)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}
		defer ISDF.DestroyKey(sesh, proKeyh)

		rootKey, uiret := ISDF.GenerateRandom(sesh, ROOTKEY_LEN)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}

		encRootKey, uiret := ISDF.Encrypt(sesh, proKeyh, ENCTYPE, nil, rootKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}

		uiret = ISDF.WriteFile(sesh, []byte(ROOTKEY_FILENAM), 0, encRootKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}

		// CBC encProKeyLen = 48
		// ECB encProKeyLen = 32
		uiret = ISDF.WriteFile(sesh, []byte(ROOTKEY_PROTECTKEY_FILENAME), 0, encProKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GenRootKey SDF Func Error")
		}
	} else {
		return b.CreateStdErr(int(uiret), "GenRootKey ProKey AlgType Error")
	}

	return nil
}

func GetRootKey(sesh unsafe.Pointer) *b.StdErr {
	list, stderr := b.ReadConfigValues("PROKEY_ENCTYPE")
	if stderr != nil {
		return stderr
	}
	protype := list["PROKEY_ENCTYPE"].([]byte)

	encRootKey, uiret := ISDF.ReadFile(sesh, []byte(ROOTKEY_FILENAM), 0, ROOTKEY_LEN)
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "GetRootKey SDF Func Error")
	}

	if bytes.Equal(protype, []byte("ECB")) {
		encProKey, uiret := ISDF.ReadFile(sesh, []byte(ROOTKEY_PROTECTKEY_FILENAME), 0, ROOTKEY_LEN*2)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GetRootKey SDF Func Error")
		}

		proKeyh, uiret := ISDF.ImportKeyWithKEK(sesh, ENCTYPE, ORGINAL_KEY_IDX, encProKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GetRootKey SDF Func Error")
		}

		rootKey, uiret := ISDF.Decrypt(sesh, proKeyh, ENCTYPE, nil, encRootKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GetRootKey SDF Func Error")
		}
		PRootKey = rootKey
	} else if bytes.Equal(protype, []byte("CBC")) {
		encProKey, uiret := ISDF.ReadFile(sesh, []byte(ROOTKEY_PROTECTKEY_FILENAME), 0, ROOTKEY_LEN*3)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GetRootKey SDF Func Error")
		}

		proKeyh, uiret := ISDF.ImportKeyWithKEK(sesh, ISDF.SGD_SM4_CBC, ORGINAL_KEY_IDX, encProKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GetRootKey SDF Func Error")
		}

		rootKey, uiret := ISDF.Decrypt(sesh, proKeyh, ENCTYPE, nil, encRootKey)
		if uiret != 0 {
			return b.CreateStdErr(int(uiret), "GetRootKey SDF Func Error")
		}
		PRootKey = rootKey
	} else {
		return b.CreateStdErr(int(uiret), "GenRootKey ProKey AlgType Error")
	}
	return nil
}
