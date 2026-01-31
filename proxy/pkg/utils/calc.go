package utils

// TrinaryOperation 三目运算
func TrinaryOperation[T interface{}](condition bool, resultA, resultB T) T {
	if condition {
		return resultA
	}
	return resultB
}

func InArray[T string | int](data T, list []T) bool {
	for _, item := range list {
		if data == item {
			return true
		}
	}
	return false
}

func Map[T any, F any](list []T, handler func(T) (F, bool)) (result []F) {
	for _, item := range list {
		value, ok := handler(item)
		if ok {
			result = append(result, value)
		}
	}
	return result
}
