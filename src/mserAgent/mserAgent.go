package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	msAPI "sig_vfy/src/mserver/API"
)

func setWritterAttribute(w *http.ResponseWriter, code int) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*") // 跨域
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(code)

}

func setWritterCode(w *http.ResponseWriter, code int) {
	(*w).WriteHeader(code)
}

var routes = map[string]http.HandlerFunc{
	"/keymanage/genkey":      tcpHandlerGenkey,
	"/keymanage/delkey":      tcpHandlerDelkey,
	"/keymanage/setprivpin":  tcpHandlerSetPrivPin,
	"/usermanage/createuser": tcpHandlerCreateUser,
	"/usermanage/deluser":    tcpHandlerDelUser,
	"/usermanage/verifyuser": tcpHandlerVerifyUser,
	"/initdev/searchinited":  tcpHandlerIfDevInited,
	"/initdev/genmainkey":    tcpHandlerGenMainKey,
	"/initdev/setinited":     tcpHandlerSetDevInited,
}

// 处理来自前端的 HTTP 请求
// 1.在指定索引上生成指定类型的密钥
func tcpHandlerGenkey(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData GenKeyRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Println("r.Body = ", r.Body)
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 2.删除指定索引上的密钥
func tcpHandlerDelkey(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData DelKeyRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Println("r.Body = ", r.Body)
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 3.为指定密钥设置私钥授权码
func tcpHandlerSetPrivPin(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData SetPswdRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Println("r.Body = ", r.Body)
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 4.创建用户
func tcpHandlerCreateUser(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)
	// var respData RespStruct
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	var requestData CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Println("r.Body = ", r.Body)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	var iret int

	if requestData.NameORuuid == 1 {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(
			requestData.PubKeyB64.B64_X + requestData.PubKeyB64.B64_Y)
		if err != nil || len(pubKeyBytes) != 128 {
			json.NewEncoder(w).Encode(RespStruct{
				Code:   "-1",
				Errmsg: "Invalid Base64 pubKey"})
			return
		}

		pubk := msAPI.ECCrefPublicKey{
			Bits: 256,
			X:    [64]byte(pubKeyBytes[:64]),
			Y:    [64]byte(pubKeyBytes[64:]),
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 5.删除用户
func tcpHandlerDelUser(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)

	// 检查请求方法
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData DelUserRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Println("r.Body = ", r.Body)
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 6.验证用户登录
func tcpHandlerVerifyUser(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)

	// 检查请求方法
	if r.Method != http.MethodPost {
		fmt.Println("r.Body = ", r.Body)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData VifyUserLoginRequest
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid JSON format"})
		return
	}

	randomBytes, err := base64.StdEncoding.DecodeString(requestData.B64Random)
	if err != nil || len(randomBytes) != 16 {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid Base64 random"})
		return
	}

	ecsigBytes, err := base64.StdEncoding.DecodeString(
		requestData.B64Ecsig.B64_R + requestData.B64Ecsig.B64_S)
	if err != nil || len(ecsigBytes) != 128 {
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Invalid Base64 ecsig"})
		return
	}

	// 调用验证用户接口
	var identity int
	iret := msAPI.Manage_VerifyUser(
		requestData.OperUserType,
		// []byte(requestData.OperUuid),
		[]byte(requestData.NameORuuid),
		[]byte(requestData.Value),
		[]byte(requestData.Value),
		[]byte(requestData.Pin),
		randomBytes,
		ecsigBytes,
		&identity)

	// 返回结果
	if iret != 0 {
		setWritterCode(&w, http.StatusInternalServerError)
	}
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 7.查询设备是否已初始化
func tcpHandlerIfDevInited(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)

	// 检查请求方法
	if r.Method != http.MethodPost {
		fmt.Println("r.Body = ", r.Body)
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
	setWritterCode(&w, http.StatusOK)
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
	setWritterAttribute(&w, http.StatusBadRequest)

	// 检查请求方法
	if r.Method != http.MethodPost {
		fmt.Println("r.Body = ", r.Body)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData GenDevMainKey
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 9.设置已初始化状态
func tcpHandlerSetDevInited(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)

	// 检查请求方法
	if r.Method != http.MethodPost {
		fmt.Println("r.Body = ", r.Body)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData SetDevInited
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// 12.密钥拆分
func tcpHandlerKeyDiv(w http.ResponseWriter, r *http.Request) {
	setWritterAttribute(&w, http.StatusBadRequest)

	// 检查请求方法
	if r.Method != http.MethodPost {
		fmt.Println("r.Body = ", r.Body)
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespWithDiv{
		RespStruct: RespStruct{
			Code:   fmt.Sprintf("%08X", iret),
			Errmsg: "",
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
	setWritterAttribute(&w, http.StatusBadRequest)

	// 检查请求方法
	if r.Method != http.MethodPost {
		fmt.Println("r.Body = ", r.Body)
		json.NewEncoder(w).Encode(RespStruct{
			Code:   "-1",
			Errmsg: "Method not allowed"})
		return
	}

	// 解析JSON请求
	var requestData KeyComeBack
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
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
	setWritterCode(&w, http.StatusOK)
	json.NewEncoder(w).Encode(RespStruct{
		Code: fmt.Sprintf("%08X", iret)})
}

// // 14.管理服务重启
// func tcpHandlerRestartMServer(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_RestartMServer(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

// // 15.重置设备
// func tcpHandlerResetAll(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_ResetAll(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

// // 16.设备自检
// func tcpHandlerDevSelfCheck(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_DevSelfCheck(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

// // 17.获取设备信息
// func tcpHandlerGetDevInfo(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_GetDevInfo(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

// // 18.设置白名单
// func tcpHandlerSetWhitTable(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_SetWhitTable(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

// // 19.删除白名单
// func tcpHandlerDelWhitTable(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_DelWhitTable(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

// // 20.获取当前设备网卡信息
// func tcpHandlerGetInterfaceInfo(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w)

// 	operUserTypeStr := r.URL.Query().Get("operusertype")
// 	operUuidStr := r.URL.Query().Get("operuuid")
// 	operUsertype, _ := strconv.Atoi(operUserTypeStr)

// 	iret := msAPI.Manage_GetInterfaceInfo(operUsertype, []byte(operUuidStr))

// 	response := fmt.Sprintf("%08X", iret)
// 	w.Header().Set("Content-Type", "text/plain")
// 	w.Write([]byte(response))
// }

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

func main() {
	for path, handler := range routes {
		http.HandleFunc(path, handler)
	}
	fmt.Println("Starting HTTP server on port 5679")
	http.ListenAndServe(":5679", nil)
}
