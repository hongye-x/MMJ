package test

import (
	"fmt"
	b "sig_vfy/src/base"
	"testing"
)

func TestReadConf(t *testing.T) {
	a, b := b.ReadConfigValues("MAX_SYM_KEY_NUM", "MAX_RSA_KEY_NUM", "MAX_SM2_KEY_NUM", "SERVER_IP")
	if b != nil {
		fmt.Println(b)
	}

	fmt.Println("MAX_SYM_KEY_NUM=", a["MAX_SYM_KEY_NUM"])
	fmt.Println("MAX_RSA_KEY_NUM=", a["MAX_RSA_KEY_NUM"])
	fmt.Println("MAX_SM2_KEY_NUM=", a["MAX_SM2_KEY_NUM"])
	fmt.Printf("SERVER_IP=%s\n", a["SERVER_IP"].([]byte))
}
