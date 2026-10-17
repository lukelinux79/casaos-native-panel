package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lukelinux79/casaos-native-panel/internal/accounts"
	"github.com/lukelinux79/casaos-native-panel/internal/api"
	"github.com/lukelinux79/casaos-native-panel/internal/audit"
	"github.com/lukelinux79/casaos-native-panel/internal/auth"
	"github.com/lukelinux79/casaos-native-panel/internal/casaos"
	"github.com/lukelinux79/casaos-native-panel/internal/config"
	"github.com/lukelinux79/casaos-native-panel/internal/runtime"
)

const usage = `usage:
  casaos-native-panel                    start the panel
  casaos-native-panel passwd <username>  set a panel password (reads it from stdin);
                                         creates an admin account if it does not exist`

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	store, err := accounts.Open(filepath.Join(cfg.DataDir, "accounts.json"))
	if err != nil {
		log.Fatalf("failed to load panel accounts: %v", err)
	}

	if len(os.Args) > 1 {
		if err := runCommand(store, os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	boot, err := auth.LoadFromEnv()
	if err != nil {
		log.Fatalf("invalid admin login config: %v", err)
	}
	switch {
	case boot.Disabled:
		log.Printf("WARNING: authentication is disabled (CASAOS_AUTH_DISABLED=true); anyone who can reach the panel has root-level control")
	case store.Len() == 0 && boot.Username == "":
		log.Fatalf("no panel account exists: set CASAOS_ADMIN_USER and CASAOS_ADMIN_PASSWORD once to create the first admin")
	case store.Len() == 0:
		if err := store.Create(boot.Username, boot.Password, accounts.RoleAdmin); err != nil {
			log.Fatalf("failed to create first admin: %v", err)
		}
		log.Printf("created first admin account %q", boot.Username)
	case boot.Username != "":
		log.Printf("panel accounts already exist; CASAOS_ADMIN_USER/CASAOS_ADMIN_PASSWORD are ignored and can be removed")
	}

	var casa *casaos.Client
	if cfg.Integration != "off" {
		casa = casaos.New(cfg.CasaOSRuntimeDir)
		target := fmt.Sprintf("http://%s:%d", gatewayTargetHost(cfg.Host), cfg.Port)
		go casa.KeepRoute(cfg.GatewayPath, target, 30*time.Second, log.Printf, nil)
	}

	rt, err := runtime.New(cfg.Mode, casa)
	if err != nil {
		log.Fatalf("failed to initialize runtime: %v", err)
	}

	srv := api.NewServer(api.Options{
		Runtime:      rt,
		Accounts:     store,
		Audit:        audit.New(filepath.Join(cfg.DataDir, "audit.log")),
		AuthDisabled: boot.Disabled,
		WebDir:       cfg.WebDir,
		CasaOS:       casa,
		BasePath:     cfg.GatewayPath,
	})
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	log.Printf("Starting CasaOS Native Panel on %s in %s mode", addr, cfg.Mode)

	server := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}

// gatewayTargetHost is the address the CasaOS gateway uses to reach the panel.
func gatewayTargetHost(listenHost string) string {
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
		return "127.0.0.1"
	}
	return listenHost
}

// runCommand handles maintenance subcommands, e.g. recovering a lost admin password.
func runCommand(store *accounts.Store, args []string) error {
	if args[0] != "passwd" || len(args) != 2 {
		return fmt.Errorf("%s", usage)
	}
	name := args[1]
	fmt.Fprintf(os.Stderr, "new password for %s: ", name)
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		// Hide the typed password on a terminal.
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		_ = off.Run()
		defer func() {
			on := exec.Command("stty", "echo")
			on.Stdin = os.Stdin
			_ = on.Run()
		}()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("no password given")
	}
	password := strings.TrimRight(line, "\r\n")

	if _, exists := store.Get(name); exists {
		if err := store.SetPassword(name, password); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\npassword of %s updated\n", name)
		return nil
	}
	if err := store.Create(name, password, accounts.RoleAdmin); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nadmin account %s created\n", name)
	return nil
}
