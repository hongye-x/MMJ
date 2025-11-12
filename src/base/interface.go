package base

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// InterfaceInfo 网络接口信息
type IPV4_InterfaceInfo struct {
	Name     [16]byte // 接口名称
	IP       [4]byte  // IP地址
	Gateway  [4]byte  // 网关地址
	Netmask  [4]byte  // 子网掩码
	IsActive int      // 网卡是否活跃
}

// 获取网络接口信息
func GetIPV4NetworkConfig() ([]IPV4_InterfaceInfo, *StdErr) {
	gateways, stderr := parseRoute()
	if stderr != nil {
		return nil, stderr
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, CreateStdErr(GET_NET_INFO_ERROR, "%s", err)
	}

	var result []IPV4_InterfaceInfo

	for _, iface := range interfaces {
		// 跳过回环接口 "lo"
		if iface.Name == "lo" {
			continue
		}

		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 转换接口名称到 [16]byte 数组
		var ifaceName [16]byte
		copy(ifaceName[:], iface.Name)

		info := IPV4_InterfaceInfo{Name: ifaceName}

		// 判断是否运行（网卡活跃）
		if iface.Flags&net.FlagRunning != 0 {
			info.IsActive = 1
		} else {
			info.IsActive = 0
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			// 转换 IP 地址为 [4]byte 数组
			copy(info.IP[:], ipNet.IP.To4())

			// 转换 Netmask 地址为 [4]byte 数组
			copy(info.Netmask[:], net.IP(ipNet.Mask).To4())

			break
		}

		if gw, exists := gateways[iface.Name]; exists {
			// 转换 Gateway 地址为 [4]byte 数组
			copy(info.Gateway[:], net.ParseIP(gw).To4())
		}

		result = append(result, info)
	}

	return result, nil
}

// 解析网关信息
func parseRoute() (map[string]string, *StdErr) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, CreateStdErr(READFILE_ERROR, "Open NetRoute File error : %08X", READFILE_ERROR)
	}
	defer file.Close()

	gateways := make(map[string]string)
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		_ = scanner.Text() // 跳过文件头
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		if ip, err := hexToIPv4(fields[2]); err == nil {
			gateways[fields[0]] = ip
		}
	}

	return gateways, nil
}

// 将十六进制字符串转换为 IPv4 地址
func hexToIPv4(hexStr string) (string, error) {
	if len(hexStr) != 8 {
		return "", fmt.Errorf("无效的十六进制字符串")
	}

	var buf bytes.Buffer
	for i := 0; i < 4; i++ {
		offset := 6 - i*2
		b, err := strconv.ParseUint(hexStr[offset:offset+2], 16, 8)
		if err != nil {
			return "", err
		}
		buf.WriteByte(byte(b))
	}

	return net.IP(buf.Bytes()).String(), nil
}

func ModifyIPV4NetworkConfig(interfaceName, ip, netmask, gateway string) *StdErr {
	if interfaceName == "" {
		return CreateStdErr(MODIFY_NET_INFO_ERROR, "Interface Name Must Be Provided")
	}

	filePath := "/etc/sysconfig/network-scripts/ifcfg-" + interfaceName
	originalContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return CreateStdErr(MODIFY_NET_INFO_ERROR, "Failed To Read Network Config: %v", err)
	}

	// 备份原文件
	backupPath := fmt.Sprintf("%s.bak", filePath)
	err = ioutil.WriteFile(backupPath, originalContent, 0644)
	if err != nil {
		return CreateStdErr(MODIFY_NET_INFO_ERROR, "Failed To Backup Original Config: %v", err)
	}

	// 准备替换规则
	var contentBuilder strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(string(originalContent)))

	ipSet, netmaskSet, gatewaySet := false, false, false

	ipRegex := regexp.MustCompile(`^IPADDR=.*`)
	netmaskRegex := regexp.MustCompile(`^NETMASK=.*`)
	gatewayRegex := regexp.MustCompile(`^GATEWAY=.*`)

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case ip != "" && ipRegex.MatchString(line):
			line = fmt.Sprintf("IPADDR=%s", ip)
			ipSet = true
		case netmask != "" && netmaskRegex.MatchString(line):
			line = fmt.Sprintf("NETMASK=%s", netmask)
			netmaskSet = true
		case gateway != "" && gatewayRegex.MatchString(line):
			line = fmt.Sprintf("GATEWAY=%s", gateway)
			gatewaySet = true
		}
		contentBuilder.WriteString(line + "\n")
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return CreateStdErr(MODIFY_NET_INFO_ERROR, "Failed Reading Config Lines: %v", err)
	}

	if ip != "" && !ipSet {
		contentBuilder.WriteString(fmt.Sprintf("IPADDR=%s\n", ip))
	}
	if netmask != "" && !netmaskSet {
		contentBuilder.WriteString(fmt.Sprintf("NETMASK=%s\n", netmask))
	}
	if gateway != "" && !gatewaySet {
		contentBuilder.WriteString(fmt.Sprintf("GATEWAY=%s\n", gateway))
	}

	err = ioutil.WriteFile(filePath, []byte(contentBuilder.String()), 0644)
	if err != nil {
		return CreateStdErr(MODIFY_NET_INFO_ERROR, "Failed To Write New Config: %v", err)
	}
	return nil
}
