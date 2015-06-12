package validation

import (
	"fmt"
)

type ErrCode int8

const (
	ErrCodeUnknownError  ErrCode = 0 //未知错误/内部错误
	ErrCodeUninitialized ErrCode = 1 //未初始化
	ErrCodeLenTooShort   ErrCode = 2 //长度太短
	ErrCodeLenTooLong    ErrCode = 3 //长度太长
	ErrCodeIllegal       ErrCode = 4 //不合法（不符合正则或不符合Hash规则）
	ErrCodeDisallowed    ErrCode = 5 //不被允许
	ErrCodeRuleNotExist  ErrCode = 6 //该字段未配置
)

const (
	errCodeUnknownErrorString  = "unknown error"
	errCodeUninitializedString = "uninitialized"
	errCodeLenTooShortString   = "length too short"
	errCodeLenTooLongString    = "length too long"
	errCodeIllegalString       = "illegal"
	errCodeDisallowedString    = "disallbowed"
	errCodeRuleNotExistString  = "field validate rule not exist"
)

var errCode2StringMap = map[ErrCode]string{
	ErrCodeUnknownError:  errCodeUnknownErrorString,
	ErrCodeUninitialized: errCodeUninitializedString,
	ErrCodeLenTooShort:   errCodeLenTooShortString,
	ErrCodeLenTooLong:    errCodeLenTooLongString,
	ErrCodeIllegal:       errCodeIllegalString,
	ErrCodeDisallowed:    errCodeDisallowedString,
	ErrCodeRuleNotExist:  errCodeRuleNotExistString,
}

type ValidateError struct {
	error
	code    ErrCode
	message string
}

func (err ValidateError) Error() string {
	return fmt.Sprintf("%d : %s", err.code, err.message)
}

func (err ValidateError) Code() ErrCode {
	return err.code
}

func (err ValidateError) Value() int8 {
	return int8(err.code)
}

func newValidateError(code ErrCode) *ValidateError {
	err := new(ValidateError)
	msg, ok := errCode2StringMap[code]
	if !ok {
		code = ErrCodeUnknownError
		msg = errCodeUnknownErrorString
	}
	err.code = code
	err.message = msg
	return err
}

func newValidateErrorByError(e error) *ValidateError {
	err := new(ValidateError)
	err.code = ErrCodeUnknownError
	err.message = errCodeUnknownErrorString + "[" + e.Error() + "]"
	return err
}
