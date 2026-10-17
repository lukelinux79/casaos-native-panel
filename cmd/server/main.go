package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lukelinux79/casaos-native-panel/internal/api"
	"github.com/lukelinux79/casaos-native-panel/internal/auth"
	"github.com/lukelinux79/casaos-native-panel/internal/config"
	"github.com/lukelinux79/casaos-native-panel/internal/runtime"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	rt, err := runtime.New(cfg.Mode)
	if err != nil {
		log.Fatalf("failed to initialize runtime: %v", err)
	}

	authCfg, err := auth.LoadFromEnv()
	if err != nil {
		log.Fatalf("invalid admin login config: %v", err)
	}
	if !authCfg.Enabled {
		log.Printf("WARNING: authentication is disabled (CASAOS_AUTH_DISABLED=true); anyone who can reach the panel has root-level control")
	}

	srv := api.NewServer(rt, authCfg, cfg.WebDir)
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	log.Printf("Starting CasaOS Native Panel on %s in %s mode", addr, cfg.Mode)

	if err := http.ListenAndServe(addr, srv.Handler()); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}
