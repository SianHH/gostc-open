package utils

import "regexp"

// 是否验证本地IP
var VALIDATE_LOCAL_IP_STATUS = true

// 验证内网IP
func ValidateLocalIP(ip string) bool {
	if !VALIDATE_LOCAL_IP_STATUS {
		return true
	}
	{
		// 验证10.0.0.0 - 10.255.255.255
		compile := regexp.MustCompile(`^10\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})$`)
		if compile.MatchString(ip) {
			return true
		}
	}
	{
		// 验证172.16.0.0 - 172.31.255.255
		compile := regexp.MustCompile(`^172\.(1[6-9]|2\d|3[01])\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})$`)
		if compile.MatchString(ip) {
			return true
		}
	}
	{
		// 验证192.168.0.0 - 192.168.255.255
		compile := regexp.MustCompile(`^192\.168\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})$`)
		if compile.MatchString(ip) {
			return true
		}
	}
	{
		// 验证127.0.0.0 - 127.255.255.255
		compile := regexp.MustCompile(`^127\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})$`)
		if compile.MatchString(ip) {
			return true
		}
	}
	return false
}

// 验证端口
func ValidatePort(port string) bool {
	compile := regexp.MustCompile("^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$")
	return compile.MatchString(port)
}

// 验证域名
func ValidateDomain(domain string) bool {
	compile := regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)
	return compile.MatchString(domain)
}
