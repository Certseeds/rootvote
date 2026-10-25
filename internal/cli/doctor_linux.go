//go:build linux

package cli

import (
	"os"
	"os/exec"
)

func extraDoctorChecks(check func(bool, string, string), warn func(string, string)) {
	if p, err := exec.LookPath("update-ca-certificates"); err == nil {
		check(true, "update-ca-certificates", p)
	} else {
		check(false, "update-ca-certificates", "未找到;Debian/Ubuntu 需要 ca-certificates")
	}
	if os.Geteuid() != 0 {
		warn("root 权限", "系统信任库操作需要 sudo")
		return
	}
	check(true, "root 权限", "uid=0")
}
