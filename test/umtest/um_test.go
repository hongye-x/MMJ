package test

import (
	"fmt"
	"os"
	"sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	"testing"
)

func TestCreateUerFile(t *testing.T) {
	devh, uierr := ISDF.OpenDevice()
	if uierr != 0 {
		fmt.Printf("OpenDevice error\n")
		t.Logf("")

	}
	defer ISDF.CloseDevice(devh)

	sesh, uierr := ISDF.OpenSession(devh)
	if uierr != 0 {
		fmt.Printf("OpenSession error\n")
		t.Logf("")
	}
	defer ISDF.CloseSession(sesh)

	var admin1uuid = "admin1"
	var admin2uuid = "admin2"
	var admin3uuid = "admin3"
	var operater1uuid = "operator1"
	var operater2uuid = "operator2"
	var operater3uuid = "operator3"
	var audit1uuid = "audit1"

	var userList = []string{admin1uuid, admin2uuid, admin3uuid, operater1uuid, operater2uuid, operater3uuid, audit1uuid}

	// var usertypeList = []int{usermanage.USER_TYPE_ADMIN, usermanage.USER_TYPE_ADMIN, usermanage.USER_TYPE_ADMIN,
	// 	usermanage.USER_TYPE_OPERA, usermanage.USER_TYPE_OPERA, usermanage.USER_TYPE_OPERA,
	// 	usermanage.USER_TYPE_AUDIT}

	var i int
	for i = 0; i < len(userList); i++ {
		uuid := userList[i]
		// pin := userList[i]
		filename1 := "../../User/" + uuid + "/pubk"
		filename2 := "../../User/" + uuid + "/pivk"

		fp1, err := os.OpenFile(filename1, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			fmt.Println(err)
			t.Logf("")
		}
		defer fp1.Close()

		fp2, err := os.OpenFile(filename2, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			fmt.Println(err)
			t.Logf("")
		}
		defer fp2.Close()

		ecpubk, ecpivk, uiret := ISDF.GenerateKeyPairECC(sesh, ISDF.SGD_SM2, 256)
		if uiret != 0 {
			fmt.Println("GenerateKeyPairECC error")
			t.Logf("")
		}

		ecpubkstr := base.ConcatSlices(ecpubk.X[:], ecpubk.Y[:])
		ecpivkstr := ecpivk.K[:]

		fmt.Println("ecpubk ", ecpubkstr)
		fmt.Println("ecpivk ", ecpivkstr)
		n, err := fp1.Write(ecpubkstr)
		fmt.Println("pubk write size = ", n)
		n, err = fp2.Write(ecpivkstr)
		fmt.Println("pivk write size = ", n)

	}
}
