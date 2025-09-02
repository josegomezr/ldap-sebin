package main

import (
	"fmt"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/merlinz01/ldapserver"
	"log"
	"strings"
	"testing"
	"time"
)

var upstreamAddr = "127.254.1.1:3389"
var subjectAddr = "127.0.1.1:3389"
var upstreamServerUrl = "ldap://" + upstreamAddr

func fakeCfg() *Cfg {
	return &Cfg{
		Verbose:        testing.Verbose(),
		Upstream:       upstreamServerUrl,
		AllowedBindDn:  "ou=Filterable OU,dc=other,dc=org",
		ListenAddr:     "",
		ListenPort:     "",
		BaseDn:         "ou=Translated Users,dc=example,dc=org",
		FilterTemplate: "(equivalentUsername=$1)",
	}
}

type fakeUpstreamHandler struct {
	ldapserver.BaseHandler
	baseDN        string
	searchResults []string
}

func (h fakeUpstreamHandler) Bind(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.BindRequest) {
	bindDN := req.Name
	var result *ldapserver.Result
	if bindDN == fmt.Sprintf("cn=AlwaysCorrect CN,%s", h.baseDN) {
		result = ldapserver.ResultSuccess.AsResult("SUCCESS!")
	} else {
		result = ldapserver.ResultInvalidCredentials.AsResult("Failed auth")
	}
	conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, result)
}

func makeSearchEntry(uid, base string) *ldapserver.SearchResultEntry {
	cn := fmt.Sprintf("cn=%s CN", uid)
	return &ldapserver.SearchResultEntry{
		ObjectName: fmt.Sprintf("%s,%s", cn, base),
		Attributes: []ldapserver.Attribute{
			{Description: "cn", Values: []string{cn}},
			{Description: "uid", Values: []string{uid}},
			{Description: "givenname", Values: []string{fmt.Sprintf("Given Name %s", uid)}},
			{Description: "sn", Values: []string{fmt.Sprintf("Last Name %s", uid)}},
		},
	}
}

func (h fakeUpstreamHandler) Search(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.SearchRequest) {
	if strings.HasSuffix(req.BaseObject, h.baseDN) {
		for _, entry := range h.searchResults {
			conn.SendResult(
				msg.MessageID,
				nil,
				ldapserver.TypeSearchResultEntryOp,
				makeSearchEntry(entry, h.baseDN),
			)
		}
	}
	conn.SendResult(msg.MessageID, nil, ldapserver.TypeSearchResultDoneOp, ldapserver.ResultSuccess.AsResult(""))
}

func shutdown(s *ldapserver.LDAPServer, name string) {
	if testing.Verbose() {
		log.Println("Stopping", name)
	}
	s.Shutdown()
}

func listen(s *ldapserver.LDAPServer, name, addr string, ready chan bool) {
	if testing.Verbose() {
		log.Println("Starting", name)
	}

	go func() {
		time.Sleep(1 * time.Millisecond)
		ready <- true
	}()
	s.ListenAndServe(addr)
}

func withServer(t *testing.T, handler ldapserver.Handler, fn func(*ldap.Conn)) {
	t.Helper()
	ready := make(chan bool, 1)

	upstream := ldapserver.NewLDAPServer(handler)
	go listen(upstream, "upstream", upstreamAddr, ready)
	<-ready
	defer shutdown(upstream, "upstream")

	s := newServer(fakeCfg())
	go listen(s, "local", subjectAddr, ready)
	<-ready
	defer shutdown(s, "local")

	conn, err := ldap.DialURL("ldap://" + subjectAddr)
	if err != nil {
		t.Fatalf("Failed: %s", err)
	}
	fn(conn)
}

func TestSearchNoResults(t *testing.T) {
	handler := &fakeUpstreamHandler{
		baseDN: "dc=example,dc=org",
	}

	withServer(t, handler, func(conn *ldap.Conn) {
		err := conn.Bind("uid=random,ou=Filterable OU,dc=other,dc=org", "password")
		if err == nil {
			t.Fatalf("expected failure")
		}
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			t.Fatalf("Expected LDAPResultNoSuchObject, got=%q", err)
		}
	})
}

func TestSearchResultsBadPW(t *testing.T) {
	handler := &fakeUpstreamHandler{
		baseDN:        "dc=example,dc=org",
		searchResults: []string{"random"},
	}

	withServer(t, handler, func(conn *ldap.Conn) {
		err := conn.Bind("uid=random,ou=Filterable OU,dc=other,dc=org", "password")
		if err == nil {
			t.Fatalf("expected failure")
		}
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			t.Fatalf("Expected LDAPResultNoSuchObject, got=%q", err)
		}
	})
}

func TestSearchOutsideOfAllowedDN(t *testing.T) {
	handler := &fakeUpstreamHandler{
		baseDN: "ou=Translated Users,dc=example,dc=org",
	}

	withServer(t, handler, func(conn *ldap.Conn) {
		err := conn.Bind("uid=who-cares-this-has-to-fail,ou=NotYourOU,dc=wooooooo,dc=org", "password")
		if err == nil {
			t.Fatalf("expected failure")
		}
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			t.Fatalf("Expected LDAPResultInsufficientAccessRights, got=%q", err)
		}
	})
}

func TestSearchResultsCorrectPW(t *testing.T) {
	handler := &fakeUpstreamHandler{
		baseDN:        "ou=Translated Users,dc=example,dc=org",
		searchResults: []string{"AlwaysCorrect"},
	}

	withServer(t, handler, func(conn *ldap.Conn) {
		err := conn.Bind("uid=this-must-work,ou=Filterable OU,dc=other,dc=org", "password")
		if err != nil {
			t.Fatalf("failed: %s", err)
		}
	})
}

func TestConfigFileEmpty(t *testing.T) {
	orig := ReadFile
	defer func() { ReadFile = orig }()
	ReadFile = func(string) ([]byte, error) {
		return []byte("---"), nil
	}
	cfg := &Cfg{}
	err := enrichConfigFromFile("", cfg)
	if err != nil {
		t.Fatalf("failed: %s", err)
	}
}

func TestConfigFileRequired(t *testing.T) {
	orig := ReadFile
	defer func() { ReadFile = orig }()
	ReadFile = func(string) ([]byte, error) {
		return []byte(
			"---" + "\n" +
				`upstream-server-url: ldap://your-ldap-server.example.com` + "\n" +
				`base-dn: "ou=Fun User Accounts,dc=company,dc=tld"` + "\n" +
				`...` + "\n",
		), nil
	}
	cfg := &Cfg{}
	err := enrichConfigFromFile("", cfg)
	if err != nil {
		t.Fatalf("failed: %s", err)
	}

	if cfg.Upstream != "ldap://your-ldap-server.example.com" {
		t.Fatalf("failed pulling cfg from yaml file. got=%q", cfg.Upstream)
	}

	if cfg.BaseDn != "ou=Fun User Accounts,dc=company,dc=tld" {
		t.Fatalf("failed pulling cfg from yaml file. got=%q", cfg.BaseDn)
	}
}

func TestConfigEnvs(t *testing.T) {
	cfg := &Cfg{}
	enrichConfigFromEnv(cfg)

	if cfg.Upstream != "" {
		t.Fatalf("failed pulling cfg from yaml file. got=%q", cfg.Upstream)
	}

	if cfg.BaseDn != "" {
		t.Fatalf("failed pulling cfg from yaml file. got=%q", cfg.BaseDn)
	}
}

func TestValidateCfg(t *testing.T) {
	cfgs := []struct {
		cfg         Cfg
		shouldError bool
	}{
		{
			cfg: Cfg{
				Upstream: "",
				BaseDn:   "",
			},
			shouldError: true,
		},
		{
			cfg: Cfg{
				Upstream: "ldap://something",
				BaseDn:   "",
			},
			shouldError: true,
		},
		{
			cfg: Cfg{
				Upstream: "ldap://something",
				BaseDn:   "dc=a,dc=b",
			},
			shouldError: false,
		},
	}

	for _, expectation := range cfgs {
		if err := validateCfg(&expectation.cfg); (err == nil) == expectation.shouldError {
			if expectation.shouldError {
				t.Fatalf("Failed, expected error: %+v", expectation.cfg)
			} else {
				t.Fatalf("Failed, unexpected error: %+v", expectation.cfg)
			}
		}
	}
}
