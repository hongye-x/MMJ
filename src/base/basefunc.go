package base

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const CONFFILE_PATH = "./config.conf"

type ServerStatus struct {
	OnBoot   int // 开机自启
	ConnNums int // 连接数
	CpuOcc   int //	cpu占用率
	MemOcc   int // 内存占用率
}

/** 错误返回类型 **/
type StdErr struct {
	Errcode int
	ErrFile string
	ErrLine int
	ErrMsg  string
}

func CreateStdErr(errcode int, format string, args ...interface{}) *StdErr {
	var err StdErr
	err.Errcode = errcode
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		err.ErrFile = "UnknownFile"
		err.ErrLine = 0
	} else {
		err.ErrFile = file
		err.ErrLine = line
	}
	err.ErrMsg = fmt.Sprintf(format, args...)
	return &err
}

func PrintStdErr(err *StdErr) {
	fmt.Printf("Error File : %s:%d\nError Code : %08X\nError Msg  : %s\n",
		err.ErrFile, err.ErrLine, err.Errcode, err.ErrMsg)
}

func ConcatSlices(slices ...[]byte) []byte {
	var result []byte
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}

func ReadConfigValues(keys ...string) (map[string]interface{}, *StdErr) {
	file, err := os.Open(CONFFILE_PATH)
	if err != nil {
		return nil, CreateStdErr(READFILE_ERROR, "Error Opening File: %v", err)
	}
	defer file.Close()

	results := make(map[string]interface{})
	for _, key := range keys {
		results[key] = nil
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		for _, key := range keys {
			if strings.HasPrefix(line, key) {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					valueStr := strings.TrimSpace(parts[1])

					if intValue, err := strconv.Atoi(valueStr); err == nil {
						results[key] = intValue
					} else {
						results[key] = []byte(valueStr)
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, CreateStdErr(READFILE_ERROR, "Error Opening File: %v", err)
	}

	return results, nil
}

func Restart() {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Println("Error: unable to get executable path")
		return
	}

	// 创建命令来重新启动程序
	cmd := exec.Command(execPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		fmt.Println("Error: unable to restart program")
		return
	}

	os.Exit(0)
}
