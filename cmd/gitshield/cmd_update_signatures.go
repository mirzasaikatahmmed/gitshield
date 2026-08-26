package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mirzasaikatahmmed/gitshield/internal/config"
	"github.com/mirzasaikatahmmed/gitshield/internal/signatures"
)

// cmdUpdateSignatures fetches a signature-set YAML file from a
// user-configured URL and, alongside it, a detached ed25519 signature at
// <url>.sig (hex-encoded). The download is refused unless it verifies
// against the pubkey pinned in config — an unauthenticated update mechanism
// would just be a new attack vector for the same campaign it's defending
// against. This is the manual entry point; autoUpdateSignatures in
// cmd_autoupdate.go does the same fetch+verify+write on a schedule.
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
	if *urlFlag != "" {
		cfg.UpdateSignaturesURL = *urlFlag
	}

	if cfg.UpdateSignaturesURL == "" {
		fmt.Fprintln(os.Stderr, "gitshield: no signatures URL configured (set update_signatures_url in config.yaml or pass --url)")
		return 2
	}
	if cfg.UpdateSignaturesPubKey == "" {
		fmt.Fprintln(os.Stderr, "gitshield: refusing to update signatures — no update_signatures_pubkey pinned in config.yaml.")
		fmt.Fprintln(os.Stderr, "An unauthenticated signature update is itself a supply-chain risk; configure the ed25519 public key of your trusted signature source first.")
		return 2
	}

	data, err := fetchVerifiedSignatures(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield:", err)
		return 2
	}

	dest, err := writeSignatures(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitshield: writing signatures file:", err)
		return 2
	}

	if gf.jsonOut {
		fmt.Printf("{\"status\":\"ok\",\"path\":%q,\"bytes\":%d}\n", dest, len(data))
	} else {
		fmt.Printf("gitshield: signature set verified and installed -> %s\n", dest)
		fmt.Println("gitshield: picked up automatically on the next clone/pull/scan (no config change needed)")
	}
	return 0
}

// fetchVerifiedSignatures downloads cfg.UpdateSignaturesURL plus its
// detached signature and returns the raw, ed25519-verified, YAML-valid
// bytes. Callers must have already confirmed URL/pubkey are configured.
func fetchVerifiedSignatures(cfg config.Config) ([]byte, error) {
	data, err := httpGet(cfg.UpdateSignaturesURL)
	if err != nil {
		return nil, fmt.Errorf("fetching signatures: %w", err)
	}
	sigHex, err := httpGet(cfg.UpdateSignaturesURL + ".sig")
	if err != nil {
		return nil, fmt.Errorf("fetching signature file: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(cfg.UpdateSignaturesPubKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update_signatures_pubkey is not a valid hex-encoded ed25519 public key")
	}
	sigBytes, err := hex.DecodeString(trimHexWhitespace(sigHex))
	if err != nil {
		return nil, fmt.Errorf("signature file is not valid hex")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), data, sigBytes) {
		return nil, fmt.Errorf("SIGNATURE VERIFICATION FAILED — refusing to install untrusted signature set")
	}

	if _, err := signatures.ParseYAML(data); err != nil {
		return nil, fmt.Errorf("downloaded signature file is not valid YAML after verification: %w", err)
	}
	return data, nil
}

// writeSignatures writes verified signature-set bytes to
// ~/.gitshield/signatures.yaml, the fixed path EffectiveSignatures always
// considers.
func writeSignatures(data []byte) (string, error) {
	dest, err := config.DefaultSignaturesPath()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", err
	}
	return dest, nil
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
