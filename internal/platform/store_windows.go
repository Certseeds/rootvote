//go:build windows

package platform

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	certStoreProvSystemW        = 10
	certSystemStoreCurrentUser  = 0x00010000
	certSystemStoreLocalMachine = 0x00020000
	certFindSHA1Hash            = 0x00010000
	x509AsnEncoding             = 0x00000001
	pkcs7AsnEncoding            = 0x00010000
	certStoreAddReplaceExisting = 3
	cryptENotFound              = 0x80092004
)

var (
	crypt32 = syscall.NewLazyDLL("crypt32.dll")

	procCertOpenStore                    = crypt32.NewProc("CertOpenStore")
	procCertCloseStore                   = crypt32.NewProc("CertCloseStore")
	procCertFindCertificateInStore       = crypt32.NewProc("CertFindCertificateInStore")
	procCertAddEncodedCertificateToStore = crypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertDeleteCertificateFromStore   = crypt32.NewProc("CertDeleteCertificateFromStore")
	procCertFreeCertificateContext       = crypt32.NewProc("CertFreeCertificateContext")
)

type cryptHashBlob struct {
	cbData uint32
	pbData *byte
}

type winStore struct {
	scope Scope
	h     syscall.Handle
}

func (s *winStore) Scope() Scope { return s.scope }

func openWinStore(scope Scope) (*winStore, error) {
	var flags uintptr
	switch scope {
	case ScopeUser:
		flags = certSystemStoreCurrentUser
	case ScopeMachine:
		flags = certSystemStoreLocalMachine
	default:
		return nil, fmt.Errorf("无效的 Windows store scope: %s", scope)
	}
	name, err := syscall.UTF16PtrFromString("Disallowed")
	if err != nil {
		return nil, err
	}
	h, _, callErr := procCertOpenStore.Call(
		certStoreProvSystemW,
		x509AsnEncoding,
		0,
		flags,
		uintptr(unsafe.Pointer(name)),
	)
	if h == 0 {
		if isAccessDenied(callErr) {
			return nil, ErrPermission
		}
		return nil, fmt.Errorf("CertOpenStore: %w", callErr)
	}
	return &winStore{scope: scope, h: syscall.Handle(h)}, nil
}

func Open(scope Scope) ([]Store, error) {
	switch scope {
	case ScopeUser:
		s, err := openWinStore(ScopeUser)
		if err != nil {
			return nil, err
		}
		return []Store{s}, nil
	case ScopeMachine:
		s, err := openWinStore(ScopeMachine)
		if err != nil {
			return nil, err
		}
		return []Store{s}, nil
	case ScopeAll:
		user, err := openWinStore(ScopeUser)
		if err != nil {
			return nil, err
		}
		machine, err := openWinStore(ScopeMachine)
		if err != nil {
			user.Close()
			return nil, err
		}
		return []Store{user, machine}, nil
	default:
		return nil, fmt.Errorf("无效的 scope: %s", scope)
	}
}

func (s *winStore) Blocked(sum [20]byte) (bool, error) { return s.contains(sum) }

func (s *winStore) Block(der []byte) (BlockResult, error) {
	sum := sha1.Sum(der)
	ok, err := s.contains(sum)
	if err != nil {
		return BlockResult{}, err
	}
	if ok {
		return BlockResult{}, nil
	}
	if err := s.add(der); err != nil {
		return BlockResult{}, err
	}
	return BlockResult{Changed: true}, nil
}

func (s *winStore) Unblock(sum [20]byte) error { return s.remove(sum) }

func (s *winStore) contains(sha1 [20]byte) (bool, error) {
	blob := cryptHashBlob{cbData: uint32(len(sha1)), pbData: &sha1[0]}
	ctx, _, callErr := procCertFindCertificateInStore.Call(
		uintptr(s.h),
		x509AsnEncoding|pkcs7AsnEncoding,
		0,
		certFindSHA1Hash,
		uintptr(unsafe.Pointer(&blob)),
		0,
	)
	if ctx == 0 {
		if isNotFound(callErr) {
			return false, nil
		}
		return false, fmt.Errorf("CertFindCertificateInStore: %w", callErr)
	}
	procCertFreeCertificateContext.Call(ctx)
	return true, nil
}

func (s *winStore) add(der []byte) error {
	if len(der) == 0 {
		return errors.New("空证书")
	}
	ok, _, callErr := procCertAddEncodedCertificateToStore.Call(
		uintptr(s.h),
		x509AsnEncoding,
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		certStoreAddReplaceExisting,
		0,
	)
	if ok == 0 {
		if isAccessDenied(callErr) {
			return ErrPermission
		}
		return fmt.Errorf("CertAddEncodedCertificateToStore: %w", callErr)
	}
	return nil
}

func (s *winStore) remove(sha1 [20]byte) error {
	blob := cryptHashBlob{cbData: uint32(len(sha1)), pbData: &sha1[0]}
	ctx, _, callErr := procCertFindCertificateInStore.Call(
		uintptr(s.h),
		x509AsnEncoding|pkcs7AsnEncoding,
		0,
		certFindSHA1Hash,
		uintptr(unsafe.Pointer(&blob)),
		0,
	)
	if ctx == 0 {
		if isNotFound(callErr) {
			return nil
		}
		return fmt.Errorf("CertFindCertificateInStore: %w", callErr)
	}
	ok, _, callErr := procCertDeleteCertificateFromStore.Call(ctx)
	if ok == 0 {
		procCertFreeCertificateContext.Call(ctx)
		if isNotFound(callErr) {
			return nil
		}
		return fmt.Errorf("CertDeleteCertificateFromStore: %w", callErr)
	}
	return nil
}

func (s *winStore) Close() error {
	if s.h != 0 {
		procCertCloseStore.Call(uintptr(s.h), 0)
		s.h = 0
	}
	return nil
}

func isNotFound(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno) == cryptENotFound
	}
	return false
}

func isAccessDenied(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}
