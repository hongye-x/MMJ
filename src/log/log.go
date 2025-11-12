package slog

import (
	"fmt"
	"sig_vfy/src/sqlop"
	"sync"
)

const (
	Debug int = iota
	Info
	Warning
	Error
	Fatal
)

var (
	logChan chan sqlop.ServerLog // 日志通道
	done    chan struct{}        // 关闭信号
	wg      sync.WaitGroup       // 等待组
	once    sync.Once            // 单次初始化
	mu      sync.Mutex           // 互斥锁
)

var AsyncRecordLog = 0                // 默认关闭密码运算服务异步日志记录
var asyncRecordCannelSize = 1024      // 异步下通道最大缓冲
var manageServerRecordLevel = Info    // ManageLog级别默认Info
var cryptoServerRecordLevel = Warning // ServerLog级别从配置中读取 默认Warning

func loglevel2String(l int) []byte {
	switch l {
	case Debug:
		return []byte("DEBUG")
	case Info:
		return []byte("INFO")
	case Warning:
		return []byte("WARNING")
	case Error:
		return []byte("ERROR")
	case Fatal:
		return []byte("FATAL")
	default:
		return []byte("UNKNOWN")
	}
}

func MServerLogWrite(loglevel, usertype int, username []byte, msg string, args ...interface{}) {
	if loglevel >= manageServerRecordLevel {
		sqlop.Gsqlh.Create(&sqlop.ManageLog{LogLevel: loglevel2String(loglevel),
			UserType: usertype, UserNameOrUUID: username, Message: fmt.Sprintf(msg, args...)})
	} else {
		return
	}
}

func CServerLogWrite(loglevel int, ip string, msg string, args ...interface{}) {
	if loglevel >= cryptoServerRecordLevel {
		if AsyncRecordLog == 0 { //sync
			sqlop.Gsqlh.Create(&sqlop.ServerLog{LogLevel: loglevel2String(loglevel),
				UserIp: []byte(ip), Message: fmt.Sprintf(msg, args...)})
		} else {
			asyncLog(loglevel, ip, msg, args...)
		}
	} else {
		return
	}
}

func LogInit(asyncflag int) {
	AsyncRecordLog = asyncflag
	if AsyncRecordLog != 0 {
		initAsyncLogger()
	}
}

func LogDeInit() {
	if AsyncRecordLog != 0 {
		shutdownLogger()
	}
}

func initAsyncLogger() {
	once.Do(func() {
		logChan = make(chan sqlop.ServerLog, asyncRecordCannelSize)
		done = make(chan struct{})
		wg.Add(1)
		go processLogs()
	})
}

func shutdownLogger() {
	mu.Lock()
	defer mu.Unlock()

	close(done)
	wg.Wait()
	close(logChan)
}

func processLogs() {
	defer wg.Done()
	for {
		select {
		case entry := <-logChan:
			sqlop.Gsqlh.Create(&entry)
		case <-done:
			for entry := range logChan {
				sqlop.Gsqlh.Create(&entry)
			}
			return
		}
	}
}

func asyncLog(loglevel int, ip string, msg string, args ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	select {
	case logChan <- sqlop.ServerLog{LogLevel: loglevel2String(loglevel),
		UserIp: []byte(ip), Message: fmt.Sprintf(msg, args...)}:
	default:
	}
}

// func EmergencyFlush() {
// 	for len(logChan) > 0 { // 持续检查通道
// 		entry := <-logChan         // 同步取出日志
// 		sqlop.Gsqlh.Create(&entry) // 直接写入存储
// 	}
// }
