//go:build !windows && !linux

package platform

import (
	"fmt"
	"runtime"
)

func Open(scope Scope) ([]Store, error) {
	return nil, fmt.Errorf("当前平台 %s 不支持 Windows 证书存储", runtime.GOOS)
}
