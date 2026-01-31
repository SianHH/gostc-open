package utils

import (
	"encoding/json"
	"strconv"
)

func StrMustInt(str string) int {
	i, _ := strconv.Atoi(str)
	return i
}

func IntMustStr(i int) string {
	return strconv.Itoa(i)
}

func StructMustBytes(data any) []byte {
	marshal, _ := json.Marshal(data)
	return marshal
}

func BytesMustStruct(data []byte, target any) {
	_ = json.Unmarshal(data, target)
}
