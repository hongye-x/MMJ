package keymanage

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"time"
	"unsafe"
)

const (
	MAX_MSG_LENGTH = 8192 // MAX_MSG_LLENGTH must be even
	SHADOW53_MAX   = 5    // Maximum number of shadows for the 53-bit secret sharing scheme
	SHADOW53_MIN   = 3    // Minimum number of shadows needed to reconstruct the secret
	SHADOW32_MAX   = 3    // Maximum number of shadows for the 32-bit secret sharing scheme
	SHADOW32_MIN   = 2    // Minimum number of shadows needed to reconstruct the secret
	PRIME_NUMBER   = 65537

	DIV_TYPE_SYM byte = byte(SYM_TYPE_FLAG) // 拆分对称密钥标识
	DIV_TYPE_SM2 byte = byte(SM2_TYPE_FLAG) // 拆分SM2密钥标识
	DIV_TYPE_RSA byte = byte(RSA_TYPE_FLAG) // 拆分RSA密钥标识
)

type ShadowShort16 struct {
	X  int32
	Fx int32
}

type ShadowMsg struct {
	X  byte
	Fx [MAX_MSG_LENGTH]byte
}

func short16Divide32(m int32) []ShadowShort16 {
	shadows := make([]ShadowShort16, SHADOW32_MAX)
	rand.Seed(time.Now().UnixNano())

	for {
		loop := false
		a := rand.Int31() & 0xFFFF
		for a <= 0 {
			a = rand.Int31() & 0xFFFF
		}

		for i := 0; i < SHADOW32_MAX; i++ {
			x := int32(i + 1)
			shadows[i] = ShadowShort16{
				X:  x,
				Fx: (a*x + m) % PRIME_NUMBER,
			}
			if shadows[i].Fx > 0xFFFF {
				loop = true
				break
			}
		}

		if !loop {
			break
		}
	}
	return shadows
}

func short16Divide53(m int32) []ShadowShort16 {
	shadows := make([]ShadowShort16, SHADOW53_MAX)
	rand.Seed(time.Now().UnixNano())

	for {
		loop := false
		a := rand.Int31() & 0xFFFF
		for a <= 0 {
			a = rand.Int31() & 0xFFFF
		}
		b := rand.Int31() & 0xFFFF
		for b <= 0 || a == b {
			b = rand.Int31() & 0xFFFF
		}

		for i := 0; i < SHADOW53_MAX; i++ {
			x := int32(i + 1)
			shadows[i] = ShadowShort16{
				X:  x,
				Fx: (a*x*x + b*x + m) % PRIME_NUMBER,
			}
			if shadows[i].Fx > 0xFFFF {
				loop = true
				break
			}
		}

		if !loop {
			break
		}
	}
	return shadows
}

func short16Comeback32(x, y ShadowShort16) int32 {
	if x == y {
		return -1
	}

	t := y.X - x.X
	s := (x.Fx * y.X) - (y.Fx * x.X)

	if t < 0 {
		t = -t
		s = -s
	}

	for s < 0 {
		s += PRIME_NUMBER
	}

	s %= PRIME_NUMBER
	t %= PRIME_NUMBER

	for s%t != 0 {
		s += PRIME_NUMBER
	}

	return (s / t) % PRIME_NUMBER
}

func short16Comeback53(x, y, z ShadowShort16) int32 {
	t := (x.X - y.X) * (y.X - z.X) * (z.X - x.X)
	s := z.X*(x.X-z.X)*(x.X*y.Fx-y.X*x.Fx) + y.X*(y.X-x.X)*(x.X*z.Fx-z.X*x.Fx)

	if t < 0 {
		t = -t
		s = -s
	}

	for s < 0 {
		s += PRIME_NUMBER
	}

	s %= PRIME_NUMBER
	t %= PRIME_NUMBER

	for s%t != 0 {
		s += PRIME_NUMBER
	}

	return (s / t) % PRIME_NUMBER
}

func MsgDivide32(msg []byte) (int, []ShadowMsg) {
	var shadow [SHADOW32_MAX]ShadowMsg
	msgLen := len(msg)
	for i := 0; i < msgLen; i += 2 {
		var m int32
		if i+1 >= msgLen {
			m = (int32(msg[i]) << 8) | int32(0)

		} else {
			m = (int32(msg[i]) << 8) | int32(msg[i+1])

		}
		shadow16 := short16Divide32(m)

		for k := 0; k < SHADOW32_MAX; k++ {
			shadow[k].X = byte(shadow16[k].X & 0xFF)
			shadow[k].Fx[i] = byte((shadow16[k].Fx >> 8) & 0xFF)
			shadow[k].Fx[i+1] = byte(shadow16[k].Fx & 0xFF)
		}
	}
	return msgLen, shadow[:]
}

func MsgDivide53(msg []byte) (int, []ShadowMsg) {
	var shadow [SHADOW53_MAX]ShadowMsg
	msgLen := len(msg)
	for i := 0; i < msgLen; i += 2 {
		var m int32
		if i+1 >= msgLen {
			m = (int32(msg[i]) << 8) | int32(0)

		} else {
			m = (int32(msg[i]) << 8) | int32(msg[i+1])

		}
		shadow16 := short16Divide53(m)

		for k := 0; k < SHADOW53_MAX; k++ {
			shadow[k].X = byte(shadow16[k].X & 0xFF)
			shadow[k].Fx[i] = byte((shadow16[k].Fx >> 8) & 0xFF)
			shadow[k].Fx[i+1] = byte(shadow16[k].Fx & 0xFF)
		}
	}
	return msgLen, shadow[:]
}

func MsgComeback32(msgLen int, x, y ShadowMsg) []byte {
	if msgLen&1 == 1 {
		msgLen += 1
	}
	var msg = make([]byte, msgLen)
	for i := 0; i < msgLen; i += 2 {
		xx := ShadowShort16{
			X:  int32(x.X),
			Fx: (int32(x.Fx[i]) << 8) | int32(x.Fx[i+1]),
		}
		yy := ShadowShort16{
			X:  int32(y.X),
			Fx: (int32(y.Fx[i]) << 8) | int32(y.Fx[i+1]),
		}
		m := short16Comeback32(xx, yy)
		msg[i] = byte((m >> 8) & 0xFF)
		msg[i+1] = byte(m & 0xFF)
	}
	return msg
}

func MsgComeback53(msgLen int, x, y, z ShadowMsg) []byte {
	if msgLen&1 == 1 {
		msgLen += 1
	}
	var msg = make([]byte, msgLen)
	for i := 0; i < msgLen; i += 2 {
		xx := ShadowShort16{
			X:  int32(x.X),
			Fx: (int32(x.Fx[i]) << 8) | int32(x.Fx[i+1]),
		}
		yy := ShadowShort16{
			X:  int32(y.X),
			Fx: (int32(y.Fx[i]) << 8) | int32(y.Fx[i+1]),
		}
		zz := ShadowShort16{
			X:  int32(z.X),
			Fx: (int32(z.Fx[i]) << 8) | int32(z.Fx[i+1]),
		}

		m := short16Comeback53(xx, yy, zz)
		msg[i] = byte((m >> 8) & 0xFF)
		msg[i+1] = byte(m & 0xFF)
	}
	return msg
}

// keytype	keyidx	keybits	serial	ekeydivlen	ekeydiv	digest
//
//	1		   4	   4	   1       	4				  32
func KeyDiv32(sesh unsafe.Pointer, keyidx int, keytype byte, rootkey []byte) ([][]byte, *b.StdErr) {
	var msg []byte
	var msglen int
	var keybits int

	k, _, stderr := GetKeyValueFromSQL(sesh, keyidx, int(keytype), rootkey)
	if stderr != nil {
		return nil, stderr
	}

	if keytype == DIV_TYPE_SYM {
		msglen = k.(*MemStorSymKey).KeyBits / 8
		msg = make([]byte, msglen)
		copy(msg, k.(*MemStorSymKey).KeyValue)
		keybits = k.(*MemStorSymKey).KeyBits
	} else if keytype == DIV_TYPE_RSA {
		msglen = int(k.(*MemStorRSAKey).PubKey.Bits/8/2) * 15
		msg = b.ConcatSlices(k.(*MemStorRSAKey).PubKey.M[:], k.(*MemStorRSAKey).PubKey.E[:],
			k.(*MemStorRSAKey).PrivKey.M[:], k.(*MemStorRSAKey).PrivKey.E[:], k.(*MemStorRSAKey).PrivKey.D[:],
			k.(*MemStorRSAKey).PrivKey.Prime[0][:], k.(*MemStorRSAKey).PrivKey.Prime[1][:],
			k.(*MemStorRSAKey).PrivKey.Pexp[0][:], k.(*MemStorRSAKey).PrivKey.Pexp[1][:],
			k.(*MemStorRSAKey).PrivKey.Coef[:])
		keybits = int(k.(*MemStorRSAKey).PubKey.Bits)

	} else if keytype == DIV_TYPE_SM2 {
		msglen = int(k.(*MemStorSM2Key).PubKey.Bits/8) * 2 * 3
		msg = b.ConcatSlices(k.(*MemStorSM2Key).PubKey.X[:], k.(*MemStorSM2Key).PubKey.Y[:],
			k.(*MemStorSM2Key).PrivKey.K[:])
		keybits = int(k.(*MemStorSM2Key).PubKey.Bits)

	} else {
		return nil, b.CreateStdErr(b.KEY_TYPE_ERROR, "Unknow Key Type : %c", keytype)
	}

	digest, uiret := ISDF.Hash(sesh, msg)
	if uiret != 0 {
		return nil, b.CreateStdErr(int(uiret), "KeyDiv32 SDF Func Error")
	}

	encmsg, iret := ISDF.EncryptEx(sesh, rootkey, ISDF.SGD_SM4_ECB, nil, msg)
	if iret != 0 {
		return nil, b.CreateStdErr(iret, "KeyDiv32 SDF Func Error")
	}

	_, shadowmsg := MsgDivide32(encmsg)

	var out = make([][]byte, SHADOW32_MAX)
	var outlen = 4 + 1 + 4 + 4 + 1 + 32 + msglen
	for i := 0; i < SHADOW32_MAX; i++ {
		out[i] = make([]byte, outlen)
		out[i][0] = keytype
		binary.BigEndian.PutUint32(out[i][1:], uint32(keyidx))
		binary.BigEndian.PutUint32(out[i][5:], uint32(keybits))
		out[i][9] = shadowmsg[i].X
		binary.BigEndian.PutUint32(out[i][10:], uint32(msglen))
		copy(out[i][14:], shadowmsg[i].Fx[:msglen])
		copy(out[i][14+msglen:], digest)
	}

	return out, nil
}

func KeyDiv53(sesh unsafe.Pointer, keyidx int, keytype byte, rootkey []byte) ([][]byte, *b.StdErr) {
	var msg []byte
	var msglen int
	var keybits int

	k, _, stderr := GetKeyValueFromSQL(sesh, keyidx, int(keytype), rootkey)
	if stderr != nil {
		return nil, stderr
	}

	if keytype == DIV_TYPE_SYM {
		msglen = k.(*MemStorSymKey).KeyBits / 8
		msg = make([]byte, msglen)
		copy(msg, k.(*MemStorSymKey).KeyValue)
		keybits = k.(*MemStorSymKey).KeyBits / 8
	} else if keytype == DIV_TYPE_RSA {
		msglen = int(k.(*MemStorRSAKey).PubKey.Bits/8/2) * 15
		msg = b.ConcatSlices(k.(*MemStorRSAKey).PubKey.M[:], k.(*MemStorRSAKey).PubKey.E[:],
			k.(*MemStorRSAKey).PrivKey.M[:], k.(*MemStorRSAKey).PrivKey.E[:], k.(*MemStorRSAKey).PrivKey.D[:],
			k.(*MemStorRSAKey).PrivKey.Prime[0][:], k.(*MemStorRSAKey).PrivKey.Prime[1][:],
			k.(*MemStorRSAKey).PrivKey.Pexp[0][:], k.(*MemStorRSAKey).PrivKey.Pexp[1][:],
			k.(*MemStorRSAKey).PrivKey.Coef[:])
		keybits = int(k.(*MemStorRSAKey).PubKey.Bits)
	} else if keytype == DIV_TYPE_SM2 {
		msglen = int(k.(*MemStorSM2Key).PubKey.Bits/8) * 3
		msg = b.ConcatSlices(k.(*MemStorSM2Key).PubKey.X[:], k.(*MemStorSM2Key).PubKey.Y[:],
			k.(*MemStorSM2Key).PrivKey.K[:])
		keybits = int(k.(*MemStorSM2Key).PubKey.Bits)

	} else {
		return nil, b.CreateStdErr(b.KEY_TYPE_ERROR, "Unknow Key Type : %c", keytype)
	}

	digest, uiret := ISDF.Hash(sesh, msg)
	if uiret != 0 {
		return nil, b.CreateStdErr(int(uiret), "KeyDiv32 SDF Func Error")
	}

	encmsg, iret := ISDF.EncryptEx(sesh, rootkey, ISDF.SGD_SM4_ECB, nil, msg)
	if iret != 0 {
		return nil, b.CreateStdErr(iret, "KeyDiv32 SDF Func Error")
	}

	_, shadowmsg := MsgDivide32(encmsg)

	var out = make([][]byte, SHADOW53_MAX)
	var outlen = 4 + 1 + 4 + 4 + 1 + 32 + msglen
	for i := 0; i < SHADOW53_MAX; i++ {
		out[i] = make([]byte, outlen)
		out[i][0] = keytype
		binary.BigEndian.PutUint32(out[i][1:], uint32(keyidx))
		binary.BigEndian.PutUint32(out[i][5:], uint32(keybits))
		out[i][9] = shadowmsg[i].X
		binary.BigEndian.PutUint32(out[i][10:], uint32(msglen))
		copy(out[i][14:], shadowmsg[i].Fx[:msglen])
		copy(out[i][14+msglen:], digest)
	}

	return out, nil
}

// keytype	keyidx	keybits	serial	ekeydivlen	ekeydiv	digest
//
//	1		   4	   4	   1       	4				  32
func KeyComeBack32(sesh unsafe.Pointer, s1, s2 []byte, rootkey []byte) *b.StdErr {
	var shadow1, shadow2 ShadowMsg
	if !bytes.Equal(s1[0:9], s2[0:9]) {
		return b.CreateStdErr(b.KEY_COMEBAK_FILE_ERROR, "KeyComeBack Component Error")
	}

	keytype := s1[0]
	keyidx := binary.BigEndian.Uint32(s1[1:])
	keybits := binary.BigEndian.Uint32(s1[5:])
	shadow1.X = s1[9]
	shadow2.X = s2[9]
	divlen := binary.BigEndian.Uint32(s1[10:])
	copy(shadow1.Fx[:], s1[14:14+divlen])
	copy(shadow2.Fx[:], s2[14:14+divlen])
	digest := s1[14+divlen:]
	enckeyv := MsgComeback32(int(divlen), shadow1, shadow2)
	keyv, iret := ISDF.DecryptEx(sesh, rootkey, ISDF.SGD_SM4_ECB, nil, enckeyv)
	if iret != 0 {
		return b.CreateStdErr(iret, "KeyComeback32 SDF Func Error")
	}

	digc, uiret := ISDF.Hash(sesh, keyv)
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "KeyComeBack SDF Func Error")
	}
	if !bytes.Equal(digc, digest) {
		return b.CreateStdErr(b.KEYCB_CHECK_ERROR, "KeyComeBack Digest Check Error")
	}

	var keyitf interface{}
	if keytype == DIV_TYPE_SYM {
		keyitf = &MemStorSymKey{}
		keyitf.(*MemStorSymKey).Idx = int(keyidx)
		keyitf.(*MemStorSymKey).KeyBits = int(keybits)
		keyitf.(*MemStorSymKey).KeyValue = make([]byte, keybits/8)
		copy(keyitf.(*MemStorSymKey).KeyValue, keyv)
	} else if keytype == DIV_TYPE_SM2 {
		keyitf = &MemStorSM2Key{}
		keyitf.(*MemStorSM2Key).Idx = int(keyidx)
		keyitf.(*MemStorSM2Key).PrivKeyAuth = 0
		keyitf.(*MemStorSM2Key).PubKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorSM2Key).PubKey.X[:], keyv[0:ISDF.ECCref_MAX_LEN])
		copy(keyitf.(*MemStorSM2Key).PubKey.Y[:], keyv[ISDF.ECCref_MAX_LEN:ISDF.ECCref_MAX_LEN*2])
		keyitf.(*MemStorSM2Key).PrivKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorSM2Key).PrivKey.K[:], keyv[ISDF.ECCref_MAX_LEN*2:ISDF.ECCref_MAX_LEN*3])

	} else if keytype == DIV_TYPE_RSA {
		keyitf = &MemStorRSAKey{}
		keyitf.(*MemStorRSAKey).Idx = int(keyidx)
		keyitf.(*MemStorRSAKey).PrivKeyAuth = 0
		keyitf.(*MemStorRSAKey).PubKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorRSAKey).PubKey.M[:], keyv[0:ISDF.LiteRSAref_MAX_LEN])
		copy(keyitf.(*MemStorRSAKey).PubKey.E[:], keyv[ISDF.LiteRSAref_MAX_LEN:ISDF.LiteRSAref_MAX_LEN*2])
		keyitf.(*MemStorRSAKey).PrivKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorRSAKey).PrivKey.M[:], keyv[ISDF.LiteRSAref_MAX_LEN*2:ISDF.LiteRSAref_MAX_LEN*3])
		copy(keyitf.(*MemStorRSAKey).PrivKey.E[:], keyv[ISDF.LiteRSAref_MAX_LEN*3:ISDF.LiteRSAref_MAX_LEN*4])
		copy(keyitf.(*MemStorRSAKey).PrivKey.D[:], keyv[ISDF.LiteRSAref_MAX_LEN*4:ISDF.LiteRSAref_MAX_LEN*5])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Prime[0][:], keyv[ISDF.LiteRSAref_MAX_LEN*5:ISDF.LiteRSAref_MAX_LEN*5+ISDF.LiteRSAref_MAX_LEN/2])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Prime[1][:], keyv[ISDF.LiteRSAref_MAX_LEN*5+ISDF.LiteRSAref_MAX_LEN/2:ISDF.LiteRSAref_MAX_LEN*6])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Pexp[0][:], keyv[ISDF.LiteRSAref_MAX_LEN*6:ISDF.LiteRSAref_MAX_LEN*6+ISDF.LiteRSAref_MAX_LEN/2])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Pexp[1][:], keyv[ISDF.LiteRSAref_MAX_LEN*6+ISDF.LiteRSAref_MAX_LEN/2:ISDF.LiteRSAref_MAX_LEN*7])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Coef[:], keyv[ISDF.LiteRSAref_MAX_LEN*7:ISDF.LiteRSAref_MAX_LEN*7+ISDF.LiteRSAref_MAX_LEN/2])

	}
	return AddKey2SQL(sesh, keyitf, rootkey)
}

func KeyComeBack53(sesh unsafe.Pointer, s1, s2, s3 []byte, rootkey []byte) *b.StdErr {
	var shadow1, shadow2, shadow3 ShadowMsg
	if !bytes.Equal(s1[0:9], s2[0:9]) {
		return b.CreateStdErr(b.KEY_COMEBAK_FILE_ERROR, "KeyComeBack Component Error")
	}
	if !bytes.Equal(s1[0:9], s3[0:9]) {
		return b.CreateStdErr(b.KEY_COMEBAK_FILE_ERROR, "KeyComeBack Component Error")
	}

	keytype := s1[0]
	keyidx := binary.BigEndian.Uint32(s1[1:])
	keybits := binary.BigEndian.Uint32(s1[5:])
	shadow1.X = s1[9]
	shadow2.X = s2[9]
	shadow3.X = s3[9]
	divlen := binary.BigEndian.Uint32(s1[10:])
	copy(shadow1.Fx[:], s1[14:14+divlen])
	copy(shadow2.Fx[:], s2[14:14+divlen])
	copy(shadow3.Fx[:], s3[14:14+divlen])
	digest := s1[14+divlen:]

	enckeyv := MsgComeback53(int(divlen), shadow1, shadow2, shadow3)
	keyv, iret := ISDF.DecryptEx(sesh, rootkey, ISDF.SGD_SM4_ECB, nil, enckeyv)
	if iret != 0 {
		return b.CreateStdErr(iret, "KeyComeback53 SDF Func Error")
	}

	digc, uiret := ISDF.Hash(sesh, keyv)
	if uiret != 0 {
		return b.CreateStdErr(int(uiret), "KeyComeBack SDF Func Error")
	}
	if !bytes.Equal(digc, digest) {
		return b.CreateStdErr(b.KEYCB_CHECK_ERROR, "KeyComeBack Digest Check Error")
	}

	var keyitf interface{}
	if keytype == DIV_TYPE_SYM {
		keyitf = &MemStorSymKey{}
		keyitf.(*MemStorSymKey).Idx = int(keyidx)
		keyitf.(*MemStorSymKey).KeyBits = int(keybits)
		keyitf.(*MemStorSymKey).KeyValue = make([]byte, keybits/8)
		copy(keyitf.(*MemStorSymKey).KeyValue, keyv)

	} else if keytype == DIV_TYPE_SM2 {
		keyitf = &MemStorSM2Key{}
		keyitf.(*MemStorSM2Key).Idx = int(keyidx)
		keyitf.(*MemStorSM2Key).PrivKeyAuth = 0
		keyitf.(*MemStorSM2Key).PubKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorSM2Key).PubKey.X[:], keyv[0:ISDF.ECCref_MAX_LEN])
		copy(keyitf.(*MemStorSM2Key).PubKey.Y[:], keyv[ISDF.ECCref_MAX_LEN:ISDF.ECCref_MAX_LEN*2])
		keyitf.(*MemStorSM2Key).PrivKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorSM2Key).PrivKey.K[:], keyv[ISDF.ECCref_MAX_LEN*2:ISDF.ECCref_MAX_LEN*3])

	} else if keytype == DIV_TYPE_RSA {
		keyitf = &MemStorRSAKey{}
		keyitf.(*MemStorRSAKey).Idx = int(keyidx)
		keyitf.(*MemStorRSAKey).PrivKeyAuth = 0
		keyitf.(*MemStorRSAKey).PubKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorRSAKey).PubKey.M[:], keyv[0:ISDF.LiteRSAref_MAX_LEN])
		copy(keyitf.(*MemStorRSAKey).PubKey.E[:], keyv[ISDF.LiteRSAref_MAX_LEN:ISDF.LiteRSAref_MAX_LEN*2])
		keyitf.(*MemStorRSAKey).PrivKey.Bits = uint(keybits)
		copy(keyitf.(*MemStorRSAKey).PrivKey.M[:], keyv[ISDF.LiteRSAref_MAX_LEN*2:ISDF.LiteRSAref_MAX_LEN*3])
		copy(keyitf.(*MemStorRSAKey).PrivKey.E[:], keyv[ISDF.LiteRSAref_MAX_LEN*3:ISDF.LiteRSAref_MAX_LEN*4])
		copy(keyitf.(*MemStorRSAKey).PrivKey.D[:], keyv[ISDF.LiteRSAref_MAX_LEN*4:ISDF.LiteRSAref_MAX_LEN*5])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Prime[0][:], keyv[ISDF.LiteRSAref_MAX_LEN*5:ISDF.LiteRSAref_MAX_LEN*5+ISDF.LiteRSAref_MAX_LEN/2])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Prime[1][:], keyv[ISDF.LiteRSAref_MAX_LEN*5+ISDF.LiteRSAref_MAX_LEN/2:ISDF.LiteRSAref_MAX_LEN*6])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Pexp[0][:], keyv[ISDF.LiteRSAref_MAX_LEN*6:ISDF.LiteRSAref_MAX_LEN*6+ISDF.LiteRSAref_MAX_LEN/2])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Pexp[1][:], keyv[ISDF.LiteRSAref_MAX_LEN*6+ISDF.LiteRSAref_MAX_LEN/2:ISDF.LiteRSAref_MAX_LEN*7])
		copy(keyitf.(*MemStorRSAKey).PrivKey.Coef[:], keyv[ISDF.LiteRSAref_MAX_LEN*7:ISDF.LiteRSAref_MAX_LEN*7+ISDF.LiteRSAref_MAX_LEN/2])

	}
	return AddKey2SQL(sesh, keyitf, rootkey)
}
