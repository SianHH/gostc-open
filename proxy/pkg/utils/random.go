package utils

import (
	"bytes"
	"math/rand"
	"time"
)

var random *rand.Rand

func init() {
	random = rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
}

const (
	LatterDict = "abcdefghijklmnopqrstuvwxyz"
	NumDict    = "0123456789"
	AllDict    = LatterDict + NumDict
)

// RandStr 生成随机字符串
func RandStr(num int, dict string) (str string) {
	if num <= 0 {
		num = 1
	}
	var buf bytes.Buffer
	for i := 0; i < num; i++ {
		buf.WriteString(string(dict[random.Intn(len(dict))]))
	}
	return buf.String()
}

// RandNum 随机数
func RandNum(n int) int {
	return random.Intn(n)
}

// RandStrPrefix 随机字符串固定前缀
func RandStrPrefix(num int, prefix string, dict string) (str string) {
	return prefix + RandStr(num, dict)
}
