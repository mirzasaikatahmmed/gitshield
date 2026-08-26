package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/mirzasaikatahmmed/gitshield/internal/config"
	"github.com/mirzasaikatahmmed/gitshield/internal/signatures"
)

// cmdUpdateSignatures fetches a signature-set YAML file from a
// user-configured URL and, alongside it, a detached ed25519 signature at
// <url>.sig (hex-encoded). The download is refused unless it verifies
// against the pubkey pinned in config — an unauthenticated update mechanism
// would just be a new attack vector for the same campaign it's defending
// against.
func cmdUpdateSignatures(args []string) int {
	fs := flag.NewFlagSet("update-signatures", flag.ContinueOnError)
	gf := parseCommonFlags(fs)
	urlFlag := fs.String("url", "", "override the signatures URL from config")
	if err := parseArgs(fs, args); err != nil {
		return 2
	}

	cfgPath := gf.configPath
	if cfgPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "gitshield:", err)
			return 2
		}
		cfgPath = p
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	url := *urlFlag
	if url == "" {
		url = cfg.UpdateSignaturesURL
	}
	if url == "" {
		fmt.Fprintln(os.Stderr, "gitshield: no signatures URL configured (set update_signatures_url in config.yaml or pass --url)")
		return 2
	}
	if cfg.UpdateSignaturesPubKey == "" {
		fmt.Fprintln(os.Stderr, "gitshield: refusing to update signatures — no update_signatures_pubkey pinned in config.yaml.")
		fmt.Fprintln(os.Stderr, "An unauthenticated signature update is itself a supply-chain risk; configure the ed25519 public key of your trusted signature source first.")
		return 2
	}

	data, err := httpGet(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: fetching signatures:", err)
		return 2
	}
	sigHex, err := httpGet(url + ".sig")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: fetching signature file:", err)
		return 2
	}

	pubKeyBytes, err := hex.DecodeString(cfg.UpdateSignaturesPubKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "gitshield: update_signatures_pubkey is not a valid hex-encoded ed25519 public key")
		return 2
	}
	sigBytes, err := hex.DecodeString(trimHexWhitespace(sigHex))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: signature file is not valid hex")
		return 2
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), data, sigBytes) {
		fmt.Fprintln(os.Stderr, "gitshield: SIGNATURE VERIFICATION FAILED — refusing to install untrusted signature set")
		return 2
	}

	if _, err := signatures.ParseYAML(data); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: downloaded signature file is not valid YAML after verification:", err)
		return 2
	}

	dir, err := config.Dir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}
	dest := filepath.Join(dir, "signatures.yaml")
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: writing signatures file:", err)
		return 2
	}

	if gf.jsonOut {
		fmt.Printf("{\"status\":\"ok\",\"path\":%q,\"bytes\":%d}\n", dest, len(data))
	} else {
		fmt.Printf("gitshield: signature set verified and installed -> %s\n", dest)
		fmt.Println("gitshield: add `signatures_file: " + dest + "` to config.yaml to use it (kept separate from the pinned default set).")
	}
	return 0
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
}

func trimHexWhitespace(b []byte) string {
	s := string(b)
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
