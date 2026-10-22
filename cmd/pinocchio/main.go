package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/LiamTang827/pinomarket/internal/live"
	"github.com/LiamTang827/pinomarket/protocol"
)

func fail(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
func read(path string, v any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func write(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func main() {
	if len(os.Args) > 1 && (os.Args[1] == "network" || os.Args[1] == "net") {
		if err := live.RunCLI(os.Args[2:]); err != nil {
			fail(err)
		}
		return
	}
	if len(os.Args) < 2 {
		fmt.Println("pinocchio network init|node|ready|open|submit|measure|wait|status|audit\npinocchio run [-scenario normal|delay|omission|refusal|equivocation|late|capacity|funds|cancel|duplicate|corrupt|drop] [-config path] [-out runs/demo]\npinocchio verify -file runs/demo/evidence.json\npinocchio audit -file runs/demo/report.json\npinocchio replay -file runs/demo/report.json")
		return
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	scenario := fs.String("scenario", "normal", "built-in scenario")
	config := fs.String("config", "", "JSON configuration")
	out := fs.String("out", "runs/demo", "new output directory")
	file := fs.String("file", "", "input report or evidence bundle")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "run":
		c, err := protocol.DefaultConfig(*scenario)
		if err != nil {
			fail(err)
		}
		if *config != "" {
			if err = read(*config, &c); err != nil {
				fail(err)
			}
		}
		r, err := protocol.Run(c)
		if err != nil {
			fail(err)
		}
		if err = os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
			fail(err)
		}
		if err = os.Mkdir(*out, 0755); err != nil {
			fail(fmt.Errorf("refuse to overwrite output: %w", err))
		}
		if err = protocol.AuditReport(*r); err != nil {
			fail(fmt.Errorf("internal report audit: %w", err))
		}
		if err = write(filepath.Join(*out, "report.json"), r); err != nil {
			fail(err)
		}
		if err = write(filepath.Join(*out, "evidence.json"), r.Audit); err != nil {
			fail(err)
		}
		f, err := os.OpenFile(filepath.Join(*out, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fail(err)
		}
		enc := json.NewEncoder(f)
		for _, e := range r.Events {
			if err = enc.Encode(e); err != nil {
				f.Close()
				fail(err)
			}
		}
		if err = f.Close(); err != nil {
			fail(err)
		}
		if err = write(filepath.Join(*out, "metrics.json"), r.Metrics); err != nil {
			fail(err)
		}
		fmt.Printf("Metrics: %+v\n", r.Metrics)
		fmt.Printf("Scenario: %s\nMODE: single-process simulation; ideal finality and ideal key vault\n", c.Name)
		for _, x := range r.Results {
			fmt.Printf("  %-12s %-20s filled=%d cost=%d cents\n", x.Order, x.Status, x.Filled, x.Cost)
		}
		fmt.Printf("Verified evidence: %d\nReport: %s\nSemantic digest: %s\n", len(r.Audit.Evidence), filepath.Join(*out, "report.json"), r.SemanticDigest)
	case "verify":
		var a protocol.AuditBundle
		if err := read(*file, &a); err != nil {
			fail(err)
		}
		n, err := protocol.VerifyAudit(a)
		if err != nil {
			fail(err)
		}
		fmt.Printf("Verified %d evidence item(s) against the supplied scenario member keys.\nThis is not proof of real-world identity or completeness.\n", n)
	case "audit":
		var r protocol.Report
		if err := read(*file, &r); err != nil {
			fail(err)
		}
		if err := protocol.AuditReport(r); err != nil {
			fail(err)
		}
		fmt.Println("Artifact audit passed: signatures, openings, certificates, FIFO service and independent market accounting. Scenario keys remain the supplied trust root; no physical-time or BFT proof.")
	case "replay":
		var old protocol.Report
		if err := read(*file, &old); err != nil {
			fail(err)
		}
		if old.Semantic() != old.SemanticDigest {
			fail(fmt.Errorf("stored semantic digest mismatch"))
		}
		r, err := protocol.Run(old.Config)
		if err != nil {
			fail(err)
		}
		if r.SemanticDigest != old.SemanticDigest {
			fail(fmt.Errorf("semantic replay mismatch"))
		}
		fmt.Println("Semantic replay matched (fresh cryptographic randomness; not a full artifact/security audit).")
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}
