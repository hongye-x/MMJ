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
	B64Shadow
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
	NameORuuid   string   `json:"nameORuuid"`
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

// 15.
