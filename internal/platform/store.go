package platform

import (
	"errors"
	"fmt"
)

type Scope string

const (
	ScopeUser    Scope = "user"
	ScopeMachine Scope = "machine"
	ScopeAll     Scope = "all"
)

var ErrPermission = errors.New("需要管理员权限")

type BlockResult struct {
	Changed    bool
	BackupPath string
}

type Store interface {
	Scope() Scope
	Blocked(sha1 [20]byte) (bool, error)
	Block(der []byte) (BlockResult, error)
	Unblock(sha1 [20]byte) error
	Close() error
}

func ParseScope(s string) (Scope, error) {
	switch Scope(s) {
	case ScopeUser, ScopeMachine, ScopeAll:
		return Scope(s), nil
	default:
		return "", fmt.Errorf("无效的 scope %q(可选 user/machine/all)", s)
	}
}
