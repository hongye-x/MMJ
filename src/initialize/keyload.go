package initialize

import (
	"bytes"
	"fmt"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	km "sig_vfy/src/keymanage"
	"unsafe"
)

func symKeyLoad(sesh unsafe.Pointer, rootKey []byte) *b.StdErr {
	symKeyList, err := km.GetKeyListFromSQL(km.SYM_TYPE_FLAG)
	if err != nil {
		return err
	}

	for i := 0; i < int(len(symKeyList)); i++ {
		keyValue, keyDigest, err :=
			km.GetKeyValueFromSQL(sesh, symKeyList[i], km.SYM_TYPE_FLAG, rootKey)
		if err != nil {
			return err
		}

		keyDigCac, ret := ISDF.Hash(sesh, keyValue.(*km.MemStorSymKey).KeyValue)
		if ret != 0 {
			return b.CreateStdErr(int(ret),
				"SymKeyCheck SDF Func Error")
		}

		if !bytes.Equal(keyDigest, keyDigCac) {
			return b.CreateStdErr(b.KEY_INTEGRALITY_ERROR,
				"SymKeyCheck Idx : %d Verify Error", symKeyList[i])
		}

		km.AddKey2Map(keyValue)
	}
	return nil
}

func sm2KeyLoad(sesh unsafe.Pointer, rootKey []byte) *b.StdErr {
	KeyList, err := km.GetKeyListFromSQL(km.SM2_TYPE_FLAG)
	if err != nil {
		return err
	}
	for i := 0; i < int(len(KeyList)); i++ {
		keyValue, keyDigest, err :=
			km.GetKeyValueFromSQL(sesh, int(KeyList[i]&0x0FFFFFFF), km.SM2_TYPE_FLAG, rootKey)
		if err != nil {
			return err
		}

		hS := b.ConcatSlices(keyValue.(*km.MemStorSM2Key).PubKey.X[:],
			keyValue.(*km.MemStorSM2Key).PubKey.Y[:],
			keyValue.(*km.MemStorSM2Key).PrivKey.K[:])

		keyDigCac, ret := ISDF.Hash(sesh, hS)
		if ret != 0 {
			return b.CreateStdErr(int(ret),
				"SM2KeyCheck SDF Func Error")
		}

		if !bytes.Equal(keyDigest, keyDigCac) {
			return b.CreateStdErr(b.KEY_INTEGRALITY_ERROR,
				"SM2KeyCheck Idx : %d Verify Error", KeyList[i])
		}

		km.AddKey2Map(keyValue)
	}
	return nil
}

func rsaKeyLoad(sesh unsafe.Pointer, rootKey []byte) *b.StdErr {
	KeyList, err := km.GetKeyListFromSQL(km.RSA_TYPE_FLAG)
	if err != nil {
		return err
	}
	for i := 0; i < int(len(KeyList)); i++ {
		keyValue, keyDigest, err :=
			km.GetKeyValueFromSQL(sesh, KeyList[i], km.RSA_TYPE_FLAG, rootKey)
		if err != nil {
			return err
		}

		hS := b.ConcatSlices(keyValue.(*km.MemStorRSAKey).PubKey.M[:],
			keyValue.(*km.MemStorRSAKey).PubKey.E[:],
			keyValue.(*km.MemStorRSAKey).PrivKey.M[:],
			keyValue.(*km.MemStorRSAKey).PrivKey.E[:],
			keyValue.(*km.MemStorRSAKey).PrivKey.D[:],
			keyValue.(*km.MemStorRSAKey).PrivKey.Prime[0][:],
			keyValue.(*km.MemStorRSAKey).PrivKey.Prime[1][:],
			keyValue.(*km.MemStorRSAKey).PrivKey.Pexp[0][:],
			keyValue.(*km.MemStorRSAKey).PrivKey.Pexp[1][:],
			keyValue.(*km.MemStorRSAKey).PrivKey.Coef[:])

		keyDigCac, ret := ISDF.Hash(sesh, hS)
		if ret != 0 {
			return b.CreateStdErr(int(ret),
				"RSAKeyCheck SDF Func Error")
		}

		if !bytes.Equal(keyDigest, keyDigCac) {
			return b.CreateStdErr(b.KEY_INTEGRALITY_ERROR,
				"RSAKeyCheck Idx : %d Verify Error", KeyList[i])
		}

		km.AddKey2Map(keyValue)
	}

	return nil
}

func KeyLoad(sesh unsafe.Pointer, rootKey []byte) *b.StdErr {
	err := symKeyLoad(sesh, rootKey)
	if err != nil {
		return err
	}
	err = sm2KeyLoad(sesh, rootKey)
	if err != nil {
		return err
	}
	err = rsaKeyLoad(sesh, rootKey)
	if err != nil {
		return err
	}
	fmt.Println("\033[32mKey Integrity Check Success\033[0m")
	return nil
}
