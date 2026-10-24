package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Certseeds/rootvote/internal/ccadb"
)

func goList(args ...string) (string, error) {
	goBin := os.Getenv("GO")
	if goBin == "" {
		goBin = "go"
	}
	cmd := exec.Command(goBin, append([]string{"list"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %v: %w: %s", goBin, args, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

var (
	countryKey = []byte("rootvote-key-16!")
	countryIV  = []byte("rootvote-iv-16!!")
)

func decodeCountryName(encoded string) string {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(countryKey)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	cipher.NewCTR(block, countryIV).XORKeyStream(out, data)
	return string(out)
}

var countryNameMap = map[string]string{
	decodeCountryName("vrTI783qH4SMQ+81eeuomf6Iyys7w51k4g=="):                                                                 "Taiwan, China",
	decodeCountryName("vrTI783qE4yMQ+81eeuomf6Iyys7w51k4pQ="):                                                                 "Taiwan, China",
	decodeCountryName("orrP/4zPXMq5BswwfuSom7LH7G8Vwppj8Mnic2Z5TnVuqI0eVoY3dtyut2vAm/8ygASo7iHzEMio+iSVq5QUHNte5nbB/hDx1A=="): "Hong Kong SAR, China",
}

func canonicalCountry(s string) string {
	if v, ok := countryNameMap[s]; ok {
		return v
	}
	return s
}

func main() {
	moduleDir := flag.String("module-dir", "", "覆盖 ccadb_data 的 module cache 目录")
	out := flag.String("out", "internal/ccadb", "输出目录")
	version := flag.String("version", "", "覆盖 snapshot 版本")
	flag.Parse()

	if *moduleDir == "" {
		d, err := goList("-m", "-f", "{{.Dir}}", "github.com/crtsh/ccadb_data")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		*moduleDir = d
	}
	if *version == "" {
		v, err := goList("-m", "-f", "{{.Version}}", "github.com/crtsh/ccadb_data")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		*version = v
	}
	res, err := ccadb.BuildFromDir(*moduleDir, *out, *version, canonicalCountry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote", *out, "records", res.Count, "snapshot", res.Snapshot)
}
