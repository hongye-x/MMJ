package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	msAPI "sig_vfy/src/mserver/API"
	"strings"
)

func setWritterAttribute(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*") // 跨域
	(*w).Header().Set("Content-Type", "application/json")
	// (*w).WriteHeader(code)

}

func setWritterCode(w *http.ResponseWriter, code int) {
	(*w).WriteHeader(code)
}

var routes = map[string]http.HandlerFunc{
	"/keymanage/genkey":     tcpHandlerGenkey,
	"/keymanage/delkey":     tcpHandlerDelkey,
	"/keymanage/setprivpin": tcpHandlerSetPrivPin,

	"/usermanage/createuser":    tcpHandlerCreateUser,
	"/usermanage/deluser":       tcpHandlerDelUser,
	"/usermanage/verifyuser":    tcpHandlerVerifyUser,
	"/usermanage/setWhiteTable": tcpHandlerSetWhitTable,
	"/usermanage/delWhiteTable": tcpHandlerDelWhitTable,

	"/initdev/searchinited": tcpHandlerIfDevInited,
	"/initdev/genmainkey":   tcpHandlerGenMainKey,
	"/initdev/setinited":    tcpHandlerSetDevInited,

	"/devmanage/restartMServer": tcpHandlerRestartMServer,
	"/devmanage/resetall":       tcpHandlerResetAll,
	"/devmanage/selfcheck":      tcpHandlerDevSelfCheck,
	"/devmanage/getdevinfo":     tcpHandlerGetDevInfo,
	"/devmanage/getIFInfo":      tcpHandlerGetInterfaceInfo,

	"/keyoper/keydiv":      tcpHandlerKeyDiv,
	"/keyoper/keycomeback": tcpHandlerKeyComeback,
}

// 处理来自前端的 HTTP 请求
// 1.在指定索引上生成指定类型的密钥
func tcpHandlerGenkey(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData GenKeyRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_GenKey(requestData.OperUserType,
		[]byte(requestData.OperUuid), requestData.KeyType,
		requestData.KeyIdx, requestData.SigORenc, requestData.KeySize,
		[]byte(requestData.Pswd))

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 2.删除指定索引上的密钥
func tcpHandlerDelkey(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData DelKeyRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_DelKey(requestData.OperUserType,
		[]byte(requestData.OperUuid), requestData.KeyType,
		requestData.KeyIdx, requestData.SigORenc)

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 3.为指定密钥设置私钥授权码
func tcpHandlerSetPrivPin(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData SetPswdRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_SetPrivKPin(requestData.OperUserType,
		[]byte(requestData.OperUuid), requestData.KeyType,
		requestData.KeyIdx, []byte(requestData.Pswd))

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 4.创建用户
func tcpHandlerCreateUser(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)
	// var respData RespStruct
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	var iret int
	if requestData.NameORuuid == 1 {
		x, err1 := base64.StdEncoding.DecodeString(
			requestData.PubKeyB64.B64_X)
		y, err2 := base64.StdEncoding.DecodeString(
			requestData.PubKeyB64.B64_Y)

		if err1 != nil || err2 != nil || len(x) != 64 || len(y) != 64 {
			setWritterCode(&w, http.StatusBadRequest)
			json.NewEncoder(w).Encode(RespStruct{
				Code:   "-1",
				Errmsg: "Invalid Base64 pubKey"})
			return
		}

		pubk := msAPI.ECCrefPublicKey{
			Bits: 256,
			X:    [64]byte(x),
			Y:    [64]byte(y),
		}
		// uuid
		iret = msAPI.Manage_CreateUser(
			requestData.OperUserType,
			[]byte(requestData.OperUuid),
			requestData.UserType,
			nil,
			[]byte(requestData.Value),
			[]byte(requestData.Pin),
			&pubk,
		)
	} else {
		// name
		iret = msAPI.Manage_CreateUser(
			requestData.OperUserType,
			[]byte(requestData.OperUuid),
			requestData.UserType,
			[]byte(requestData.Value),
			nil,
			[]byte(requestData.Pin),
			nil,
		)
	}

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 5.删除用户
func tcpHandlerDelUser(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData DelUserRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	// 调用删除用户接口
	var iret int
	if requestData.NameORuuid == 0 {
		// 按名称删除
		iret = msAPI.Manage_DelUser(
			requestData.OperUserType,
			[]byte(requestData.OperUuid),
			[]byte(requestData.Value),
			nil)
	} else {
		// 按UUID删除
		iret = msAPI.Manage_DelUser(
			requestData.OperUserType,
			[]byte(requestData.OperUuid),
			nil,
			[]byte(requestData.Value))
	}

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 6.验证用户登录
func tcpHandlerVerifyUser(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData VifyUserLoginRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	randomBytes, err := base64.StdEncoding.DecodeString(requestData.B64Random)
	if err != nil || len(randomBytes) != 16 {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid Base64 random"})
		return
	}

	c1, err1 := base64.StdEncoding.DecodeString(
		requestData.B64Ecsig.B64_R)
	c2, err2 := base64.StdEncoding.DecodeString(
		requestData.B64Ecsig.B64_S)
	if err1 != nil || err2 != nil || len(c1) != 64 || len(c2) != 64 {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid Base64 ecsig"})
		return
	}
	ecsigBytes := append(c1, c2...)

	// 调用验证用户接口
	var identity int
	var nou []byte
	if requestData.NameORuuid == 1 {
		nou = []byte("1")
	} else if requestData.NameORuuid == 0 {
		nou = []byte("0")
	} else {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid NameORuuid"})
		return
	}

	var iret int
	if requestData.NameORuuid == 0 { // name
		iret = msAPI.Manage_VerifyUser(
			requestData.OperUserType,
			nou,
			[]byte(requestData.Value),
			nil,
			[]byte(requestData.Pin),
			randomBytes,
			ecsigBytes,
			&identity)
	} else {
		iret = msAPI.Manage_VerifyUser( // uuid
			requestData.OperUserType,
			nou,
			nil,
			[]byte(requestData.Value),
			[]byte(requestData.Pin),
			randomBytes,
			ecsigBytes,
			&identity)
	}

	// 返回结果
	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 7.查询设备是否已初始化
func tcpHandlerIfDevInited(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespWithInited{
			RespStruct: RespStruct{
				Code:   "-1",
				Errmsg: "Method not allowed",
			},
		})
		return
	}

	// 解析JSON请求
	var requestData SearchIfDevInited
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespWithInited{
			RespStruct: RespStruct{
				Code:   "-1",
				Errmsg: "Method not allowed",
			},
		})
		return
	}

	// 调用验证用户接口
	iret := msAPI.Manage_IfDevInited(
		requestData.OperUserType, []byte(requestData.OperUuid))

	// 返回结果

	json.NewEncoder(w).Encode(RespWithInited{
		RespStruct: RespStruct{
			Code:   fmt.Sprintf("%08X", iret),
			Errmsg: "",
		},
		IfInited: iret,
	})
}

// 8.生成设备根密钥
func tcpHandlerGenMainKey(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData GenDevMainKey
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_GenRootKey(
		requestData.OperUserType, []byte(requestData.OperUuid))

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 9.设置已初始化状态
func tcpHandlerSetDevInited(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData SetDevInited
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_SetDevInited(
		requestData.OperUserType, []byte(requestData.OperUuid))

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 12.密钥拆分
func tcpHandlerKeyDiv(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespWithDiv{
			RespStruct: RespStruct{
				Code:   "-1",
				Errmsg: "Method not allowed",
			},
		})
		return
	}

	// 解析JSON请求
	var requestData KeyDiv
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespWithDiv{
			RespStruct: RespStruct{
				Code:   "-1",
				Errmsg: "Method not allowed",
			},
		})
		return
	}

	var s []byte
	var bs [5]string
	iret := msAPI.Manage_KeyDiv(
		requestData.OperUserType, []byte(requestData.OperUuid), requestData.DivType,
		requestData.KeyIdx, requestData.KeyType, requestData.SigORenc, &s)
	// 返回结果
	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	} else {
		var ay = 0
		var i = 0
		var offset = 0
		if requestData.DivType == 0 {
			ay = 3
		} else if requestData.DivType == 1 {
			ay = 5
		}

		for i = 0; i < ay; i++ {
			len := binary.BigEndian.Uint32(s[offset:])
			offset += 4
			bs[i] = base64.StdEncoding.EncodeToString(s[offset : offset+int(len)])
			offset += int(len)
		}
	}

	json.NewEncoder(w).Encode(RespWithDiv{
		RespStruct: RespStruct{
			Code:   fmt.Sprintf("%08X", iret),
			Errmsg: errmap[iret],
		},
		B64Shadow: B64Shadow{
			B64_S0: bs[0],
			B64_S1: bs[1],
			B64_S2: bs[2],
			B64_S3: bs[3],
			B64_S4: bs[4],
		},
	})
}

// 13.密钥合成
func tcpHandlerKeyComeback(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData KeyComeBack
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}
	var s0, s1, s2 []byte
	s0, _ = base64.StdEncoding.DecodeString(requestData.B64_S0)
	s1, _ = base64.StdEncoding.DecodeString(requestData.B64_S1)
	if requestData.DivType == 1 {
		s2, _ = base64.StdEncoding.DecodeString(requestData.B64_S2)
	}

	iret := msAPI.Manage_KeyComeback(
		requestData.OperUserType, []byte(requestData.OperUuid),
		requestData.DivType,
		s0, s1, s2)

	// 返回结果
	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 14.管理服务重启
func tcpHandlerRestartMServer(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData DevRestartMServer
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_RestartMServer(
		requestData.OperUserType, []byte(requestData.OperUuid))

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 15.重置设备
func tcpHandlerResetAll(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData DevResetAll
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_ResetAll(
		requestData.OperUserType, []byte(requestData.OperUuid))

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 16.设备自检
func tcpHandlerDevSelfCheck(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData DevSelfCheck
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_DevSelfCheck(
		requestData.OperUserType, []byte(requestData.OperUuid),
		requestData.Flag)

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 17.获取设备信息
func tcpHandlerGetDevInfo(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData DevInfo
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	var devinf msAPI.DeviceInof
	iret := msAPI.Manage_GetDevInfo(
		requestData.OperUserType, []byte(requestData.OperUuid), &devinf)

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespWithDevinfo{
		RespStruct: RespStruct{
			Code:   fmt.Sprintf("%08X", iret),
			Errmsg: errmap[iret],
		},
		BDevInfo: BDevInfo{
			IssuerName:      string(devinf.IssuerName[:]),
			DeviceName:      string(devinf.DeviceName[:]),
			DeviceSerial:    string(devinf.DeviceSerial[:]),
			DeviceVersion:   devinf.DeviceVersion,
			StandardVersion: devinf.StandardVersion,
			AsymAlgAbility:  devinf.AsymAlgAbility,
			SymAlgAbility:   devinf.SymAlgAbility,
			HashAlgAbility:  devinf.HashAlgAbility,
			BufferSize:      devinf.BufferSize,
		},
	})
}

// 18.设置白名单
func tcpHandlerSetWhitTable(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData WhitTable
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_SetWhitTable(
		requestData.OperUserType, []byte(requestData.OperUuid),
		[]byte(requestData.Cidr))

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 19.删除白名单
func tcpHandlerDelWhitTable(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData WhitTable
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	iret := msAPI.Manage_DelWhitTable(
		requestData.OperUserType, []byte(requestData.OperUuid),
		[]byte(requestData.Cidr))

	// 返回结果

	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(RespStruct{
		Code:   fmt.Sprintf("%08X", iret),
		Errmsg: errmap[iret]})
}

// 20.获取当前设备网卡信息
func tcpHandlerGetInterfaceInfo(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w)

	// 检查请求方法
	if r.Method != http.MethodPost {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData Ipv4IfInfo
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		setWritterCode(&w, http.StatusBadRequest)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}
	var ifinfo []msAPI.IPV4_InterfaceInfo
	iret := msAPI.Manage_GetInterfaceInfo(
		requestData.OperUserType, []byte(requestData.OperUuid),
		&ifinfo)

	// 返回结果
	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}

	// 转换数据结构
	var infos []BIFInof
	for _, iface := range ifinfo {
		infos = append(infos, BIFInof{
			Name:     strings.TrimRight(string(iface.Name[:]), "\x00"),
			IP:       net.IP(iface.IP[:]).String(),
			Gateway:  net.IP(iface.Gateway[:]).String(),
			Netmask:  net.IP(iface.Netmask[:]).String(),
			IsActive: iface.IsActive,
		})
	}

	response := struct {
		RespStruct
		Interfaces []BIFInof `json:"interfaces"`
	}{
		RespStruct: RespStruct{
			Code:   fmt.Sprintf("%08X", iret),
			Errmsg: errmap[iret],
		},
		Interfaces: infos,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// // 21.修改网络配置
// func tcpHandlerModifyInterfaceInfo(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_ModifyInterfaceInfo(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

var errmap map[int]string

func createErrMap() {
	errmap = make(map[int]string)
	// 通用错误
	errmap[UNKNOW_ERROR] = "Unknow Error"
	errmap[OPENFILE_ERROR] = "File Open Error"
	errmap[READFILE_ERROR] = "File Read Error"
	errmap[SQL_CONNECT_ERROR] = "Database Connection Error"
	errmap[SQL_CREATETB_ERROR] = "Database Table Creation Error"
	errmap[SQL_SELECT_ERROR] = "Database Query Error"
	errmap[SQL_INSERT_ERROR] = "Database Insert Error"
	errmap[UNKNOW_CMD] = "Unknown Command"
	errmap[OUTOF_MAX_CONNECTION] = "Maximum Connection Limit Reached"
	errmap[ALG_SELF_TEST_ERROR] = "Algorithm Self-Test Failed"
	errmap[KEY_INTEGRALITY_ERROR] = "Key Integrity Check Failed"
	errmap[CONNECT_TO_CSERVER_ERROR] = "Failed to Connect to Crypto Server"
	errmap[DEV_NOT_INITED] = "Device Not Initialized"
	errmap[UNALBE_DEL_DEPENDENCIES] = "Unable to Delete Dependencies"
	errmap[GET_NET_INFO_ERROR] = "Failed to Get Network Information"
	errmap[MODIFY_NET_INFO_ERROR] = "Failed to Modify Network Configuration"
	errmap[UNKNOW_IPTYPE] = "Unknown IP Type"
	errmap[ACCESS_DENIED] = "Access Denied"
	errmap[RPC_REGORCALL_ERROR] = "RPC Registration or Call Error"

	// keymanage
	errmap[KEY_TYPE_ERROR] = "Key Type Error"
	errmap[STORKEY_INTERNAL_EXIST] = "Key with Specified Index Already Exists in Internal Storage"
	errmap[KEY_INSQL_NOEXIST] = "Key Does Not Exist in Database"
	errmap[PIV_PIN_SET_ERROR] = "Private Key PIN Setting Failed"
	errmap[KEY_COMEBAK_FILE_ERROR] = "Key Recovery File Error"
	errmap[KEYCB_CHECK_ERROR] = "Key Recovery Check Error"

	// init
	errmap[POWERONDET_RANDLEN_ERROR] = "Power-On Detection Random Number File Length Error"
	errmap[POWERONDET_RANDRES_ERROR] = "Power-On Detection Failed"
	errmap[CYCDET_RANDLEN_ERROR] = "Periodic Detection Random Number File Length Error"
	errmap[CYCDET_RANDRES_ERROR] = "Periodic Detection Failed"

	// usermanage
	errmap[ADMIN_NUMS_OUTOF_LIMIT] = "Administrator Count Exceeds Maximum Limit"
	errmap[OPERA_NUMS_OUTOF_LIMIT] = "Operator Count Exceeds Maximum Limit"
	errmap[AUDIT_NUMS_OUTOF_LIMIT] = "Auditor Count Exceeds Maximum Limit"
	errmap[USER_NOT_REGISTERED] = "User Not Registered"
	errmap[USER_PIN_ERROR] = "User PIN Error"
	errmap[ADMIN_CANNOT_DEL] = "Cannot Delete the Only Administrator"
	errmap[USERNAME_USERUUID_CONFLICT] = "Username and UKEY UUID Conflict"
	errmap[ASN1TYPE_ERROR] = "Non-ASN1 Type Error"

	/** 0018 **/
	errmap[SDR_UNKNOWERR] = "Unknow Error"
	errmap[SDR_NOTSUPPORT] = "Func Not Support"
	errmap[SDR_COMMFAIL] = "Device Connect Error"
	errmap[SDR_HARDFAIL] = "Crypto Mode Error"
	errmap[SDR_OPENDEVICE] = "Device Open Error"
	errmap[SDR_OPENSESSION] = "Session Open Error"
	errmap[SDR_PARDENY] = "No Private Key Access Right"
	errmap[SDR_KEYNOTEXIST] = "Key Not Exist"
	errmap[SDR_ALGNOTSUPPORT] = "Alg Not Support"
	errmap[SDR_ALGMODNOTSUPPORT] = "AlgMode Not Support"
	errmap[SDR_PKOPERR] = "Public Key Operate Error"
	errmap[SDR_SKOPERR] = "Private Key Operate Error"
	errmap[SDR_SIGNERR] = "Sign Error"
	errmap[SDR_VERIFYERR] = "Verify Error"
	errmap[SDR_SYMOPERR] = "Sym Operate Error"
	errmap[SDR_STEPERR] = "Caculate Setp Error"
	errmap[SDR_FILESIZEERR] = "File Size Error"
	errmap[SDR_FILENOEXIST] = "File Not Exist"
	errmap[SDR_FILEOFSERR] = "File Offset Error"
	errmap[SDR_KEYTYPEERR] = "Key Type Error"
	errmap[SDR_KEYERR] = "Key Error"
	errmap[SDR_ENCDATAERR] = "Ecc Cipher Error"
	errmap[SDR_RANDERR] = "Generate Random Error"
	errmap[SDR_PRKRERR] = "Get Private Key Access Right Error"
	errmap[SDR_MACERR] = "Mac Error"
	errmap[SDR_FILEEXISTS] = "File Exist"
	errmap[SDR_FILEWERR] = "File Write Error"
	errmap[SDR_NOBUFFER] = "Memory Not Enough"
	errmap[SDR_INARGERR] = "Param Input Error"
	errmap[SDR_OUTARGERR] = "Param Output Error"
}

func main() {
	createErrMap()
	for path, handler := range routes {
		http.HandleFunc(path, handler)
	}
	fmt.Println("Starting HTTP server on port 5679")
	http.ListenAndServe(":5679", nil)
}
