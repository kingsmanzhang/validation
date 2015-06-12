package validation

import (
	"regexp"
	"strings"
)

//通用屏蔽词汇
var shieldingWords []string = nil
var fieldRules map[string]*fieldRule = nil

type fieldRule struct {
	name           string
	maxLength      uint
	minLength      uint
	isRequired     bool
	isHash         bool
	useShielding   bool
	useRegExp      bool
	needEncrypt    bool
	regExpStr      string
	regExp         *regexp.Regexp
	encryptSalt    string
	disAllowedList []string
}

func Validate(name, value string, isNew bool) (string, *ValidateError) {
	if fieldRules == nil {
		return value, newValidateError(ErrCodeUninitialized)
	}
	rule, ok := fieldRules[name]
	if !ok {
		return value, newValidateError(ErrCodeRuleNotExist)
	}
	//允许为空时
	if value == "" && !rule.isRequired {
		return value, nil
	}
	
	length := uint(len(value))
	//是Hash后的密文（限制是32为hash密文）
	if rule.isHash {
		if length != 32 {
			return value, newValidateError(ErrCodeIllegal)
		}
		return value, nil
	}
	
	//是新建立的值，false就是纯加密
	if isNew {
		if length < rule.minLength {
			return value, newValidateError(ErrCodeLenTooShort)
		}
		if length > rule.maxLength {
			return value, newValidateError(ErrCodeLenTooLong)
		}
		if rule.useRegExp {
			//rule.regExp == nil的情况已在加载配置文件是处理
			if !rule.regExp.MatchString(value) {
				return value, newValidateError(ErrCodeIllegal)
			}
		}
		if rule.useShielding {
			if isDisallowed(value, shieldingWords, false) {
				return value, newValidateError(ErrCodeDisallowed)
			}
		}
		if rule.disAllowedList != nil && len(rule.disAllowedList) != 0 {
			if isDisallowed(value, rule.disAllowedList, false) {
				return value, newValidateError(ErrCodeDisallowed)
			}
		}
	}
	//需要加密则加密
	if rule.needEncrypt {
		value = hashMD5(value, rule.encryptSalt)
	}
	return value, nil
}

// 检查是否被允许（支持前后通配符*）
func isDisallowed(value string, disallowedList []string, isCaseSensitive bool) bool {
	if !isCaseSensitive {
		value = strings.ToLower(value)
	}
	for _, v := range disallowedList {
		if !isCaseSensitive {
			v = strings.ToLower(v)
		}
		if strings.Contains(v, "*") { //包含通配符
			var prefix, suffix bool = false, false
			if strings.HasPrefix(v, "*") {
				prefix = true
			}
			if strings.HasSuffix(v, "*") {
				suffix = true
			}
			v = strings.Trim(v, "*")
			//通配符在两侧
			if prefix && suffix && strings.Contains(value, v) {
				return true
				//通配符在前
			} else if prefix && strings.HasSuffix(value, v) {
				return true
				//通配符在后
			} else if suffix && strings.HasPrefix(value, v) {
				return true
			}
		} else {
			if value == v {
				return true
			}
		}
	}
	return false
}
