package nss

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Executor interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

type ExecExecutor struct{}

func (ExecExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type Certutil struct {
	Path    string
	Timeout time.Duration
	Exec    Executor
}

type Entry struct {
	Nick  string
	Trust string
}

func New(path string) *Certutil {
	return &Certutil{Path: path, Timeout: 10 * time.Second, Exec: ExecExecutor{}}
}

func (c *Certutil) run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	if c.Path == "" {
		return nil, nil, errors.New("NSS certutil 路径为空")
	}
	exec := c.Exec
	if exec == nil {
		exec = ExecExecutor{}
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	return exec.Run(ctx, c.Path, args...)
}

func (c *Certutil) HasPrimaryPassword(ctx context.Context, profileDir string) (bool, error) {
	empty, err := os.CreateTemp("", "rootvote-pw-*")
	if err != nil {
		return true, err
	}
	name := empty.Name()
	empty.Close()
	defer os.Remove(name)

	stdout, stderr, runErr := c.run(ctx, "-d", "sql:"+profileDir, "-L", "-n", "__rootvote_probe__", "-f", name)
	if runErr == nil {
		return false, nil
	}
	text := strings.ToLower(string(stdout) + " " + string(stderr))
	for _, marker := range []string{"password", "pin", "sec_error_bad_password", "sec_error_need_secret_pin", "enter password"} {
		if strings.Contains(text, marker) {
			return true, nil
		}
	}
	if strings.Contains(text, "not found") || strings.Contains(text, "could not find") {
		return false, nil
	}
	return true, fmt.Errorf("无法判断主密码状态: %w: %s", runErr, strings.TrimSpace(string(stderr)))
}

func (c *Certutil) HasNickname(ctx context.Context, profileDir, nick string) (bool, error) {
	_, _, err := c.run(ctx, "-d", "sql:"+profileDir, "-L", "-n", nick)
	if err == nil {
		return true, nil
	}
	return false, nil
}

func (c *Certutil) Add(ctx context.Context, profileDir, nick string, pemBytes []byte) error {
	f, err := os.CreateTemp("", "rootvote-cert-*.pem")
	if err != nil {
		return err
	}
	name := f.Name()
	if _, err := f.Write(pemBytes); err != nil {
		f.Close()
		os.Remove(name)
		return err
	}
	f.Close()
	defer os.Remove(name)

	_, stderr, err := c.run(ctx, "-d", "sql:"+profileDir, "-A", "-n", nick, "-t", "p,p,p", "-i", name)
	if err != nil {
		return fmt.Errorf("certutil -A: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

func (c *Certutil) SetTrust(ctx context.Context, profileDir, nick, trust string) error {
	_, stderr, err := c.run(ctx, "-d", "sql:"+profileDir, "-M", "-n", nick, "-t", trust)
	if err != nil {
		return fmt.Errorf("certutil -M: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

func (c *Certutil) Delete(ctx context.Context, profileDir, nick string) error {
	_, stderr, err := c.run(ctx, "-d", "sql:"+profileDir, "-D", "-n", nick)
	if err != nil {
		return fmt.Errorf("certutil -D: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

func (c *Certutil) ListEntries(ctx context.Context, profileDir string) ([]Entry, error) {
	stdout, stderr, err := c.run(ctx, "-d", "sql:"+profileDir, "-L")
	if err != nil {
		return nil, fmt.Errorf("certutil -L: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	var out []Entry
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "Certificate Nickname") || strings.Contains(line, "SSL,S/MIME") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		trust := fields[len(fields)-1]
		nick := strings.Join(fields[:len(fields)-1], " ")
		out = append(out, Entry{Nick: nick, Trust: trust})
	}
	return out, scanner.Err()
}

func (c *Certutil) Export(ctx context.Context, profileDir, nick string) ([]byte, error) {
	stdout, stderr, err := c.run(ctx, "-d", "sql:"+profileDir, "-L", "-n", nick, "-a")
	if err != nil {
		return nil, fmt.Errorf("certutil 导出: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	return stdout, nil
}
