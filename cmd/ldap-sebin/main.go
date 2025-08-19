package main

import (
	"fmt"
	"log"

	"os"

	"github.com/josegomezr/ldap-sebin/internal/handler"
	"github.com/merlinz01/ldapserver"
	"gopkg.in/yaml.v3"
	"sync"
)

type Cfg struct {
	Upstream       string `yaml:"upstream-server-uri"`
	ListenAddr     string `yaml:"listen-address"`
	ListenPort     int    `yaml:"listen-port"`
	Certificate    string `yaml:"certificate"`
	Key            string `yaml:"key"`
	BaseDn         string `yaml:"base-dn"`
	FilterTemplate string `yaml:"filter-template"`
}

func main() {
	data, err := os.ReadFile("./config.yaml")
	if err != nil {
		log.Fatalf("error: %+v", err)
	}

	cfg := Cfg{}
	err = yaml.Unmarshal([]byte(data), &cfg)
	if err != nil {
		log.Fatalf("error: %+v", err)
	}
	fmt.Printf("--- cfg:\n%+v\n\n", cfg)

	handler := &handler.Handler{
		Sessions:       make(map[string]handler.Session),
		LdapUri:        cfg.Upstream,
		BaseDn:         cfg.BaseDn,
		FilterTemplate: cfg.FilterTemplate,
		Mutex:          &sync.Mutex{},
	}

	s := ldapserver.NewLDAPServer(handler)

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "localhost"
	}

	var srvErr error

	if cfg.Certificate == "" || cfg.Key == "" {
		log.Println("No certificate and/or key configured. Listening for plain text connections. This is NOT secure.")

		listenPort := cfg.ListenPort
		if listenPort == 0 {
			listenPort = 389
		}

		srvErr = s.ListenAndServe(fmt.Sprintf("%s:%d", listenAddr, listenPort))
	} else {
		err := s.SetupTLS(cfg.Certificate, cfg.Key)
		if err != nil {
			log.Fatalf("TLS configuration failed: %s", err)
		}

		listenPort := cfg.ListenPort
		if listenPort == 0 {
			listenPort = 636
		}

		srvErr = s.ListenAndServeTLS(fmt.Sprintf("%s:%d", listenAddr, listenPort))
	}

	if srvErr != nil {
		log.Fatalf("Failed to start LDAP server: %s", srvErr)
	}
}
