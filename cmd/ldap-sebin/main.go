package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"errors"
	"flag"
	"github.com/josegomezr/ldap-sebin/internal/handler"
	"github.com/merlinz01/ldapserver"
	"gopkg.in/yaml.v3"
	"strconv"
	"sync"
)

type Cfg struct {
	Verbose        bool   `yaml:"verbose"`
	Upstream       string `yaml:"upstream-server-url"`
	ListenAddr     string `yaml:"listen-address"`
	ListenPort     string `yaml:"listen-port"`
	Certificate    string `yaml:"certificate"`
	Key            string `yaml:"key"`
	BaseDn         string `yaml:"base-dn"`
	FilterTemplate string `yaml:"filter-template"`
	AllowedBindDn  string `yaml:"allowed-bind-dn"`
}

func newHandler(cfg *Cfg) *handler.Handler {
	return &handler.Handler{
		AllowedBindDn:  cfg.AllowedBindDn,
		Verbose:        cfg.Verbose,
		Sessions:       make(map[string]handler.Session),
		LdapUrl:        cfg.Upstream,
		BaseDn:         cfg.BaseDn,
		FilterTemplate: cfg.FilterTemplate,
		Mutex:          &sync.Mutex{},
	}
}
func newServer(cfg *Cfg) *ldapserver.LDAPServer {
	handler := newHandler(cfg)
	return ldapserver.NewLDAPServer(handler)
}

var ReadFile func(string) ([]byte, error) = os.ReadFile
var ErrBadConfigFile error = errors.New("Bad config file")
var ErrMissingRequired error = errors.New("Bad config file")

func enrichConfigFromFile(path string, cfg *Cfg) error {
	data, err := ReadFile(path)
	if err != nil {
		return errors.Join(ErrBadConfigFile, err)
	}

	err = yaml.Unmarshal([]byte(data), cfg)

	if err != nil {
		return errors.Join(ErrBadConfigFile, err)
	}

	return nil
}

func enrichConfigFromEnv(cfg *Cfg) {
	if val, found := os.LookupEnv("LDAP_SEBIN_UPSTREAM_SERVER_URL"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_UPSTREAM_SERVER_URL value %q", val)
		} else {
			cfg.Upstream = val
		}
	}
	if val, found := os.LookupEnv("LDAP_SEBIN_LISTEN_ADDRESS"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_LISTEN_ADDRESS value %q", val)
		} else {
			cfg.ListenAddr = val
		}
	}
	if val, found := os.LookupEnv("LDAP_SEBIN_CERTIFICATE"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_CERTIFICATE value %q", val)
		} else {
			cfg.Certificate = val
		}
	}
	if val, found := os.LookupEnv("LDAP_SEBIN_KEY"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_KEY value %q", val)
		} else {
			cfg.Key = val
		}
	}
	if val, found := os.LookupEnv("LDAP_SEBIN_BASE_DN"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_BASE_DN value %q", val)
		} else {
			cfg.BaseDn = val
		}
	}
	if val, found := os.LookupEnv("LDAP_SEBIN_FILTER_TEMPLATE"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_FILTER_TEMPLATE value %q", val)
		} else {
			cfg.FilterTemplate = val
		}
	}
	if val, found := os.LookupEnv("LDAP_SEBIN_LISTEN_PORT"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_LISTEN_PORT value %q", val)
		} else {
			if _, err := strconv.Atoi(val); err == nil {
				cfg.ListenPort = val
			} else {
				log.Printf("Ignoring invalid LDAP_SEBIN_LISTEN_PORT value %q", val)
			}
		}
	}
	if val, found := os.LookupEnv("LDAP_SEBIN_VERBOSE"); found {
		if val == "" {
			log.Printf("Ignoring empty LDAP_SEBIN_VERBOSE value")
		} else {
			if boolval, err := strconv.ParseBool(val); err == nil {
				cfg.Verbose = boolval
			} else {
				log.Printf("Ignoring invalid LDAP_SEBIN_VERBOSE value %q", val)
			}
		}
	}
}

func validateCfg(cfg *Cfg) error {
	if cfg.Upstream == "" || cfg.BaseDn == "" {
		return errors.Join(ErrMissingRequired, fmt.Errorf("Incomplete upstream configuration."))
	}
	return nil
}

var (
	Version        = "dev"
	CommitHash     = "n/a"
	BuildTimestamp = "n/a" // If we wanna make it reproduceable, this should be commit date
)

func main() {
	var nFlag = flag.Bool("v", false, "version")
	flag.Parse()

	if *nFlag {
		fmt.Printf("ldap-sebin/%s\nCommit Hash: %s\nCommit Date: %s", Version, CommitHash, BuildTimestamp)
		os.Exit(0)
	}

	cfg := &Cfg{}
	if err := enrichConfigFromFile("./config.yaml", cfg); err != nil {
		log.Printf("error reading config file: %+v. IGNORING", err)
	}

	enrichConfigFromEnv(cfg)

	if err := validateCfg(cfg); err != nil {
		log.Fatalf("Invalid config: %s", err)
	}

	if cfg.Verbose {
		log.Printf("Parsed configuration")
		log.Printf("---")
		enc := yaml.NewEncoder(os.Stdout)
		enc.Encode(*cfg)
		log.Printf("---")
	}

	s := newServer(cfg)

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "localhost"
	}

	var srvErr error

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		fmt.Println()
		log.Println("Shutting down.")
		s.Shutdown()
	}()

	// TODO: make this prettier on the validation fn maybe a bool fn "tls
	// enabled" on the config struct can make it easier.

	listenFunc := s.ListenAndServe
	var listenPort string
	if !(cfg.Certificate == "" || cfg.Key == "") {
		err := s.SetupTLS(cfg.Certificate, cfg.Key)
		if err != nil {
			log.Fatalf("TLS configuration failed: %s", err)
		}
		listenFunc = s.ListenAndServeTLS
		if cfg.ListenPort != "" {
			listenPort = cfg.ListenPort
		} else {
			listenPort = "636"
		}
	} else {
		if cfg.ListenPort != "" {
			listenPort = cfg.ListenPort
		} else {
			listenPort = "389"
		}
		log.Println("No certificate and/or key configured. Listening for plain text connections. This is NOT secure.")
	}

	serverAddr := net.JoinHostPort(listenAddr, listenPort)
	log.Printf("Listening to %s", serverAddr)
	srvErr = listenFunc(serverAddr)

	if srvErr != nil {
		log.Fatalf("Failed to start LDAP server: %s", srvErr)
	}
}
