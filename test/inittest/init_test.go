package test

import (
	"crypto/rand"
	"fmt"
	"os"
	b "sig_vfy/src/base"
	ISDF "sig_vfy/src/crypto"
	i "sig_vfy/src/initialize"
	"testing"
)

func TestAlgCorrectnessCheck(t *testing.T) {
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

	var flag byte = (i.SM2_SE_TEST_FLAG | i.SM3_TEST_FLAG | i.SM4_TEST_FLAG)
	err := i.AlgCorrectnessCheck(sesh, flag)
	if err != nil {
		b.PrintStdErr(err)
		t.Logf("")
	}
}

func TestKeyLoad(t *testing.T) {
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

	err := i.GetRootKey(sesh)
	if err != nil {
		b.PrintStdErr(err)
		t.Logf("")
	}

	err = i.KeyLoad(sesh, i.PRootKey)
	if err != nil {
		b.PrintStdErr(err)
		t.Logf("")
	}
}

func genrandom(fileName string) {
	const fileSize = b.POD_PERBITLEN * b.POD_CYCLE / 8
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("无法创建文件: %v", err)
	}
	defer file.Close()

	buffer := make([]byte, fileSize)
	_, err = rand.Read(buffer)
	if err != nil {
		fmt.Printf("无法生成随机数据: %v", err)
	}
	_, err = file.Write(buffer)
	if err != nil {
		fmt.Printf("无法写入文件: %v", err)
	}
}

func TestPowerOnDetection(t *testing.T) {
	filename := "./random_data.bin"
	// genrandom(filename)
	res, err := i.RandomPowerOnDetection(filename)
	if err != nil {
		b.PrintStdErr(err)
	}

	for i := 0; i < len(res); i++ {
		if res[i] == 0 {
			t.Fatalf("Func PowerOnDetection Error")
		}
	}
}

func TestCycleDetection(t *testing.T) {
	filename := "./random_data.bin"
	// genrandom(filename)
	res, err := i.RandomCycleDetection(filename)
	if err != nil {
		b.PrintStdErr(err)
	}

	for i := 0; i < len(res); i++ {
		if res[i] == 0 {
			t.Fatalf("Func CycleDetection Error")
		}
	}
}

func TestGenRootKey(t *testing.T) {
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

	err := i.GenRootKey(sesh)
	if err != nil {
		b.PrintStdErr(err)
		t.Logf("")
	}

	err = i.GetRootKey(sesh)
	if err != nil {
		b.PrintStdErr(err)
		t.Logf("")
	}

}
