package whitetable

import (
	"fmt"
	"net"
	"sig_vfy/src/base"
	"sig_vfy/src/sqlop"
	"strings"
)

var ipNets []*net.IPNet

func LoadIPNetsFromDB() *base.StdErr {
	var records []sqlop.IPWhiteTable
	if err := sqlop.Gsqlh.Find(&records).Error; err != nil {
		return base.CreateStdErr(base.SQL_SELECT_ERROR, "IP Table Load error : %v", err)
	}

	ipNets = make([]*net.IPNet, 0, len(records))
	for _, record := range records {
		_, ipNet, err := parseIPNetwork(string(record.IP))
		if err != nil {
			continue
		}
		ipNets = append(ipNets, ipNet)
	}
	return nil
}

// 检查IP是否在白名单
func CheckIPFromIPNets(ip string) int {
	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return 0
	}

	for _, ipNet := range ipNets {
		if ipNet.Contains(targetIP) {
			return 1
		}
	}
	return 0
}

func AddCIDR2IPNets(cidr string) *base.StdErr {
	return addRecord(cidr)
}

func DelCIDRFromIPNets(cidr string) *base.StdErr {
	return delRecord(cidr)
}

// 通用添加记录函数
func addRecord(entry string) *base.StdErr {
	// 验证输入格式
	if _, _, err := parseIPNetwork(entry); err != nil {
		return base.CreateStdErr(base.SQL_INSERT_ERROR, "IP/CIDR Type error : %v", err)
	}

	var count int64
	err := sqlop.Gsqlh.Model(&sqlop.IPWhiteTable{}).Where("ip = ?", entry).Count(&count).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_INSERT_ERROR, "Add IP/CIDR Record error : %v", err)
	}
	if count == 0 {
		// 插入数据库
		result := sqlop.Gsqlh.Create(&sqlop.IPWhiteTable{IP: []byte(entry)}).
			FirstOrCreate(&sqlop.IPWhiteTable{})
		if result.Error != nil {
			return base.CreateStdErr(base.SQL_INSERT_ERROR, "Add IP/CIDR Record error : %v", result.Error)
		}
		// 重新加载白名单
		return LoadIPNetsFromDB()
	}
	return nil
}

func delRecord(entry string) *base.StdErr {
	// 验证输入格式
	if _, _, err := parseIPNetwork(entry); err != nil {
		return base.CreateStdErr(base.SQL_INSERT_ERROR, "IP/CIDR Type error : %v", err)
	}

	err := sqlop.Gsqlh.Where("ip = ?", entry).Delete(&sqlop.IPWhiteTable{}).Error
	if err != nil {
		return base.CreateStdErr(base.SQL_INSERT_ERROR, "Del IP/CIDR Record error : %v", err)
	}
	return nil
}

// 解析IP/CIDR格式
func parseIPNetwork(input string) (*net.IP, *net.IPNet, error) {
	// 尝试解析为CIDR格式
	ip, ipNet, err := net.ParseCIDR(input)
	if err == nil {
		return &ip, ipNet, nil
	}

	// 尝试解析为普通IP地址
	ip = net.ParseIP(input)
	if ip != nil {
		// 根据IP类型自动添加掩码
		if ip.To4() != nil {
			return &ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}

	return nil, nil, fmt.Errorf("invalid CIDR format")
}

func GetClientIP(conn net.Conn) (string, *base.StdErr) {
	remoteAddr := conn.RemoteAddr().String()

	// 处理 IPv6 地址的方括号（如 [::1]:12345）
	if strings.Contains(remoteAddr, "[") {
		remoteAddr = strings.Split(remoteAddr, "]")[0] + "]"
	}

	// 分割 IP 和端口
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", base.CreateStdErr(base.UNKNOW_ERROR, "Get Client IP error : %v", err)
	}

	// 去除 IPv6 地址的方括号
	ip = strings.Trim(ip, "[]")

	// 验证 IP 格式
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", base.CreateStdErr(base.UNKNOW_ERROR, "Get Client IP error : %v", err)
	}

	return ip, nil
}
