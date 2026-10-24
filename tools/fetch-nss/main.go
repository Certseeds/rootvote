package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Certseeds/rootvote/internal/nssfetch"
)

var nssFiles = []string{
	"mingw64/bin/certutil.exe",
	"mingw64/bin/nss3.dll",
	"mingw64/bin/nssutil3.dll",
	"mingw64/bin/freebl3.dll",
	"mingw64/bin/softokn3.dll",
	"mingw64/bin/nssckbi.dll",
	"mingw64/bin/smime3.dll",
	"mingw64/bin/ssl3.dll",
}

var nsprFiles = []string{
	"mingw64/bin/libnspr4.dll",
	"mingw64/bin/libplc4.dll",
	"mingw64/bin/libplds4.dll",
}

var sqliteFiles = []string{
	"mingw64/bin/libsqlite3-0.dll",
}

var zlibFiles = []string{
	"mingw64/bin/zlib1.dll",
}

func filesFor(url string) []string {
	switch {
	case strings.Contains(url, "mingw-w64-x86_64-nss-"):
		return nssFiles
	case strings.Contains(url, "mingw-w64-x86_64-nspr-"):
		return nsprFiles
	case strings.Contains(url, "mingw-w64-x86_64-sqlite3-"):
		return sqliteFiles
	case strings.Contains(url, "mingw-w64-x86_64-zlib-"):
		return zlibFiles
	default:
		return nil
	}
}

func allFiles() []string {
	out := append([]string{}, nssFiles...)
	out = append(out, nsprFiles...)
	out = append(out, sqliteFiles...)
	out = append(out, zlibFiles...)
	return out
}

func main() {
	lockPath := flag.String("lock", "tools/nss.lock", "lock 文件")
	outDir := flag.String("out", "dist/tools/nss", "输出目录")
	flag.Parse()

	f, err := os.Open(*lockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pkgs, err := nssfetch.ParseLock(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, pkg := range pkgs {
		want := filesFor(pkg.URL)
		if len(want) == 0 {
			fmt.Fprintln(os.Stderr, "未知包类型:", pkg.URL)
			os.Exit(1)
		}
		if err := nssfetch.DownloadAndExtract(context.Background(), pkg, *outDir, want); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	for _, name := range allFiles() {
		if _, err := os.Stat(filepath.Join(*outDir, filepath.Base(name))); err != nil {
			fmt.Fprintln(os.Stderr, "缺少文件:", name, err)
			os.Exit(1)
		}
	}
	fmt.Println("NSS tools written to", *outDir)
}
