package ISV

import (
	"bytes"
	"crypto"
	"crypto/elliptic"

	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"sig_vfy/src/keymanage"
	"sig_vfy/src/sigvfy/sv0029_asn1"
	"unsafe"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// CSRRequestParams 定义所有可定制的CSR参数
type CSRRequestParams struct {
	// 必填字段
	Subject pkix.Name // 证书主体信息

	// 可选字段
	DNSNames        []string         // SAN DNS名称
	EmailAddresses  []string         // SAN 邮箱地址
	IPAddresses     []net.IP         // SAN IP地址
	ExtraExtensions []pkix.Extension // 自定义扩展

	SignatureAlgorithm x509.SignatureAlgorithm // 签名算法
	PublicKeyAlgorithm x509.PublicKeyAlgorithm // 公钥算法
}

// SDFSigner 实现crypto.Signer接口
type Signer struct {
	sesh      unsafe.Pointer // 句柄
	keytype   int            // 密钥类型
	keyidx    int            // 索引
	keysv     int            // 0:sig 1:enc
	pivpin    []byte         // 私钥授权码
	id        []byte         //
	publicKey *sm2.PublicKey // 对应的SM2公钥
}

// 转换为标准SM2公钥结构
func (s *Signer) convertECCrefToPublicKey() (*sm2.PublicKey, error) {
	var realkeyidx int
	if s.keytype == keymanage.SM2_TYPE_FLAG {
		realkeyidx = s.keyidx * 2
		if s.keysv == 0 {
			realkeyidx -= 1
		}
	}

	if keymanage.MemSM2Map[realkeyidx] == nil {
		return nil, fmt.Errorf("Key Not Exist Inside")
	}
	var sdfKey = keymanage.MemSM2Map[realkeyidx].PubKey

	var curve elliptic.Curve
	switch sdfKey.Bits {
	case 256:
		curve = sm2.P256Sm2() // 国密SM2曲线
	default:
		return nil, fmt.Errorf("unsupported key bits: %d", sdfKey.Bits)
	}

	keyBytes := int(sdfKey.Bits / 8)
	if keyBytes <= 0 || keyBytes > len(sdfKey.X) {
		return nil, fmt.Errorf("invalid key length")
	}

	xBytes := sdfKey.X[keyBytes:]
	yBytes := sdfKey.Y[keyBytes:]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &sm2.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (s *Signer) Public() crypto.PublicKey {
	var err error
	if s.publicKey == nil {
		s.publicKey, err = s.convertECCrefToPublicKey()
		if err != nil {
			return err
		}
	}
	return s.publicKey
}

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var realkeyidx int
	if s.keytype == keymanage.SM2_TYPE_FLAG {
		realkeyidx = s.keyidx * 2
		if s.keysv == 0 {
			realkeyidx -= 1
		}
	}
	if s.sesh == nil {
		return nil, fmt.Errorf("Sign Session Handle Error")
	}

	sdfKey := keymanage.MemSM2Map[realkeyidx]

	if sdfKey.PrivKeyAuth == 0 {
	} else {
		dig, iret := ISDF.Hash(s.sesh, s.pivpin)
		if iret != 0 {
			return nil, fmt.Errorf("Sign SDF Func Error Code[%08X]", iret)
		}

		if !bytes.Equal(dig, sdfKey.PrivPin[:]) {
			return nil, fmt.Errorf("Sign PivPin Error Code[%08X]", base.SDR_PRKRERR)
		}
	}

	iret := ISDF.HashInit(s.sesh, ISDF.SGD_SM3, &sdfKey.PubKey, s.id)
	if iret != 0 {
		return nil, fmt.Errorf("Sign SDF Func Error Code[%08X]", iret)
	}
	iret = ISDF.HashUpdate(s.sesh, digest)
	if iret != 0 {
		return nil, fmt.Errorf("Sign SDF Func Error Code[%08X]", iret)
	}
	realdig, iret := ISDF.HashFinal(s.sesh)
	if iret != 0 {
		return nil, fmt.Errorf("Sign SDF Func Error Code[%08X]", iret)
	}

	outsig, iret := ISDF.ExternalSignECC(s.sesh,
		ISDF.SGD_SM2_1, &sdfKey.PrivKey, realdig)
	if iret != 0 {
		return nil, fmt.Errorf("Sign Error Code[%08X]", iret)
	} else {
		var boutsig []byte = make([]byte, 64)
		copy(boutsig[:32], outsig.R[32:])
		copy(boutsig[32:], outsig.S[32:])
		s, _ := sv0029_asn1.Encode_bSM2Sig_2_asn1RawSM2sig(boutsig, 10)
		return s.Bytes, nil
	}
}

func SignerInit(devh unsafe.Pointer, keytype int, keyidx int, keysv int,
	keypin, id []byte) *Signer {
	if id == nil {
		id = []byte(base.SM2_DEFAULT_ID)
	}
	sesh, _ := ISDF.OpenSession(devh)
	return &Signer{sesh: sesh,
		keytype: keytype,
		keyidx:  keyidx,
		keysv:   keysv,
		pivpin:  keypin,
		id:      id}
}

func SignerDestory(s *Signer) {
	ISDF.CloseSession(s.sesh)
	s.publicKey = nil
	s = nil
}

func CsrParamsCreater(
	Country, Organization, OrganizationalUnit []string,
	Locality, Province, StreetAddress, PostalCode []string,
	SerialNumber, CommonName string,
	DNSNames, EmailAddresses []string,
	IPAddresses []net.IP,
	ExtraExtensions []pkix.Extension,
	SignatureAlgorithm x509.SignatureAlgorithm,
	PublicKeyAlgorithm x509.PublicKeyAlgorithm,
) *CSRRequestParams {

	setIfNotEmpty := func(dest *[]string, src []string) {
		if src != nil {
			*dest = src
		}
	}

	subject := pkix.Name{
		SerialNumber: SerialNumber,
		CommonName:   CommonName,
	}

	setIfNotEmpty(&subject.Country, Country)
	setIfNotEmpty(&subject.Organization, Organization)
	setIfNotEmpty(&subject.OrganizationalUnit, OrganizationalUnit)
	setIfNotEmpty(&subject.Locality, Locality)
	setIfNotEmpty(&subject.Province, Province)
	setIfNotEmpty(&subject.StreetAddress, StreetAddress)
	setIfNotEmpty(&subject.PostalCode, PostalCode)

	return &CSRRequestParams{
		Subject:            subject,
		DNSNames:           DNSNames,
		EmailAddresses:     EmailAddresses,
		IPAddresses:        IPAddresses,
		ExtraExtensions:    ExtraExtensions,
		SignatureAlgorithm: SignatureAlgorithm,
		PublicKeyAlgorithm: PublicKeyAlgorithm,
	}
}

func GenCSRBy_SM2Key(params *CSRRequestParams, s *Signer) (asn1csr []byte, err error) {
	if s == nil {
		return nil, fmt.Errorf("必须提供有效的签名器(Signer)")
	}

	template := &x509.CertificateRequest{
		Subject:         params.Subject,
		DNSNames:        params.DNSNames,
		EmailAddresses:  params.EmailAddresses,
		IPAddresses:     params.IPAddresses,
		ExtraExtensions: params.ExtraExtensions,
	}

	if params.SignatureAlgorithm == 0 {
		template.SignatureAlgorithm = x509.SM2WithSM3
	} else {
		template.SignatureAlgorithm = params.SignatureAlgorithm
	}

	if _, ok := s.Public().(*sm2.PublicKey); ok {
		template.PublicKeyAlgorithm = x509.SM2
	} else {
		template.PublicKeyAlgorithm = params.PublicKeyAlgorithm
	}

	return x509.CreateCertificateRequest(nil, template, s)
}
