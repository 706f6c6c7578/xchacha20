package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20"
)

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	var (
		keyStr   = flag.String("k", "", "32-byte key in hex or raw format")
		nonceStr = flag.String("n", "", "24-byte nonce in hex or raw format")
		hexMode  = flag.Bool("hex", false, "interpret key and nonce as hex strings")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `XChaCha20 encryption/decryption tool

Usage: %s -k <key> -n <nonce> [-hex] < infile > outfile

Options:
  -k string    32-byte key (64 characters if hex)
  -n string    24-byte nonce (48 characters if hex)
  -hex         interpret key and nonce as hex strings (default: raw bytes)

The program reads from stdin and writes to stdout. Use input/output redirection for files.

Examples:
  Raw bytes:   %s -k "32-bytes-key-exactly-32-bytes!!" -n "24-bytes-nonce-exactly!!" < input.txt > output.bin
  Hex format:  %s -hex -k 404142...5f60 -n 404142...5f < input.txt > output.bin
`, os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	if *keyStr == "" || *nonceStr == "" {
		fmt.Fprintln(os.Stderr, "Error: Key and nonce are required")
		flag.Usage()
		os.Exit(1)
	}

	var keyBytes, nonceBytes []byte
	var err error

	if *hexMode {
		keyBytes, err = hex.DecodeString(*keyStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hex key: %v\n", err)
			os.Exit(1)
		}
		nonceBytes, err = hex.DecodeString(*nonceStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hex nonce: %v\n", err)
			os.Exit(1)
		}
	} else {
		keyBytes = []byte(*keyStr)
		nonceBytes = []byte(*nonceStr)
	}

	keyBuf := memguard.NewBufferFromBytes(keyBytes)
	nonceBuf := memguard.NewBufferFromBytes(nonceBytes)
	defer keyBuf.Destroy()
	defer nonceBuf.Destroy()

	key := keyBuf.Bytes()
	nonce := nonceBuf.Bytes()

	if len(key) != chacha20.KeySize {
		fmt.Fprintf(os.Stderr, "Error: Invalid key size. Expected %d bytes, got %d bytes\n", chacha20.KeySize, len(key))
		os.Exit(1)
	}

	if len(nonce) != chacha20.NonceSizeX {
		fmt.Fprintf(os.Stderr, "Error: Invalid nonce size. Expected %d bytes, got %d bytes\n", chacha20.NonceSizeX, len(nonce))
		os.Exit(1)
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cipher: %v\n", err)
		os.Exit(1)
	}

	secureBuf := memguard.NewBuffer(8192)
	defer secureBuf.Destroy()

	for {
		n, err := os.Stdin.Read(secureBuf.Bytes())
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			os.Exit(1)
		}
		if n == 0 {
			break
		}

		workingBuf := secureBuf.Bytes()[:n]
		cipher.XORKeyStream(workingBuf, workingBuf)
		
		if _, err := os.Stdout.Write(workingBuf); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}

		if err == io.EOF {
			break
		}
	}
}
