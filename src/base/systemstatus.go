package base

import (
	"io/ioutil"
	"strconv"
	"strings"
)

type SystemStatus struct {
	Uptime      int
	CPUUsage    int
	MemoryUsage int
}

// 获取开机时间
func getUptime() (int, *StdErr) {
	data, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return 0, CreateStdErr(OPENFILE_ERROR, "Get UpTime Error : %v", err)
	}
	fields := strings.Fields(string(data))
	uptimeSec, _ := strconv.ParseFloat(fields[0], 64)
	return int(uptimeSec), nil
}

// 获取 CPU 使用率
func getCpuUsage() (int, *StdErr) {
	data, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, CreateStdErr(OPENFILE_ERROR, "Get Cpu Usage Error : %v", err)
	}
	fields := strings.Fields(string(data))
	loadAvg, _ := strconv.ParseFloat(fields[0], 64) // 取1分钟平均负载
	return int(loadAvg), nil
}

// 获取内存使用率
func getMemoryUsage() (int, *StdErr) {
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, CreateStdErr(OPENFILE_ERROR, "Get Memory Usage Error : %v", err)
	}
	lines := strings.Split(string(data), "\n")
	var total, available uint64
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			total, _ = strconv.ParseUint(fields[1], 10, 64)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			available, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	used := total - available
	usagePercent := (float64(used) / float64(total)) * 100
	return int(usagePercent), nil
}

func GetSystemStats() (*SystemStatus, *StdErr) {
	var stats SystemStatus
	var err *StdErr

	stats.Uptime, err = getUptime()
	if err != nil {
		return &stats, err
	}

	stats.CPUUsage, err = getCpuUsage()
	if err != nil {
		return &stats, err
	}

	stats.MemoryUsage, err = getMemoryUsage()
	if err != nil {
		return &stats, err
	}

	return &stats, nil
}
