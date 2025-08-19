package main

import (
	"fmt"
	"log"

	"os"

	"beryju.io/ldap"
	"github.com/josegomezr/ldap-sebin/internal/handler"
	"gopkg.in/yaml.v3"
	"sync"
)

type Cfg struct {
	Server         string `yaml:"server"`
	TLS            bool   `yaml:"tls"`
	Port           int    `yaml:"port"`
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

	s := ldap.NewServer()

	handler := &handler.Handler{
		Sessions:       make(map[string]handler.Session),
		LdapServer:     cfg.Server,
		LdapPort:       cfg.Port,
		Tls:            cfg.TLS,
		BaseDn:         cfg.BaseDn,
		FilterTemplate: cfg.FilterTemplate,
		Mutex:          &sync.Mutex{},
	}
	s.BindFunc("", handler)
	s.CloseFunc("", handler)

	if err := s.ListenAndServe("localhost:3388"); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}
