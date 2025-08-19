package handler

// very shameful copy of beryju.io/ldap proxy example

import (
	"beryju.io/ldap"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

type Handler struct {
	Sessions       map[string]Session
	LdapServer     string
	LdapPort       int
	Tls            bool
	BaseDn         string
	FilterTemplate string
	Mutex          *sync.Mutex
}

type Session struct {
	id   string
	c    net.Conn
	ldap *ldap.Conn
}

func (h Handler) dial() (*ldap.Conn, error) {
	if h.Tls {
		fmt.Printf("Starting TLS Connection\n")
		roots, _ := x509.SystemCertPool()
		Config := &tls.Config{
			CipherSuites: []uint16{
				// TLS 1.0 - 1.2 cipher suites.
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				// TLS 1.3 cipher suites.
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			InsecureSkipVerify: true,
			RootCAs:            roots,
		}

		return ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", h.LdapServer, h.LdapPort), Config)
	}

	fmt.Printf("Starting PLAIN Connection\n")
	return ldap.Dial("tcp", fmt.Sprintf("%s:%d", h.LdapServer, h.LdapPort))
}

func (h Handler) getSession(conn net.Conn) (Session, error) {
	id := connID(conn)

	h.Mutex.Lock()
	s, ok := h.Sessions[id] // use server connection if it exists
	h.Mutex.Unlock()

	if !ok { // open a new server connection if not
		l, err := h.dial()
		if err != nil {
			fmt.Printf("ERR: %s\n", err.Error())
			return Session{}, err
		}
		// l.Debug = true

		s = Session{id: id, c: conn, ldap: l}
		h.Mutex.Lock()
		h.Sessions[s.id] = s
		h.Mutex.Unlock()
	}
	return s, nil
}

func (h Handler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	searchFilter := bindDN
	searchFilter, _, _ = strings.Cut(searchFilter, ",")
	_, searchFilter, _ = strings.Cut(searchFilter, "=")

	searchFilter = strings.ReplaceAll(h.FilterTemplate, "$1", searchFilter)
	log.Printf("input bind-dn: %+v\n", bindDN)
	log.Printf("search-filter: %+v\n", searchFilter)

	search := ldap.NewSearchRequest(
		h.BaseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 0, false,
		searchFilter,
		[]string{"dn"},
		nil)

	s, err := h.getSession(conn)
	if err != nil {
		return ldap.LDAPResultOperationsError, err
	}
	log.Printf("Performing search: %+v ", search)

	sr, err := s.ldap.Search(search)
	if err != nil {
		return ldap.LDAPResultOperationsError, err
	}

	var lastError error

	if len(sr.Entries) == 0 {
		return ldap.LDAPResultNoSuchObject, nil
	}

	for _, entry := range sr.Entries {
		newDn := entry.DN
		log.Printf("Search matched DN: %+v ", newDn)

		if err := s.ldap.Bind(newDn, bindSimplePw); err != nil {
			log.Printf("Failed auth, continuing")
			lastError = err
			continue
		}

		log.Printf("Auth succeeded!: %+v ", newDn)
		return ldap.LDAPResultSuccess, nil
	}

	log.Printf("Failed auth against all matched entries")
	return ldap.LDAPResultInvalidCredentials, lastError
}

func (h Handler) Close(boundDN string, conn net.Conn) error {
	log.Printf("Closing connection")

	conn.Close() // close connection to the server when then client is closed
	h.Mutex.Lock()
	defer h.Mutex.Unlock()
	delete(h.Sessions, connID(conn))
	return nil
}

func connID(conn net.Conn) string {
	h := sha1.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}
