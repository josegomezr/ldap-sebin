package handler

// very shameful copy of beryju.io/ldap proxy example

import (
	"crypto/sha1"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
	"github.com/merlinz01/ldapserver"
)

type Handler struct {
	ldapserver.BaseHandler

	Verbose        bool
	AllowedBindDn  string
	Sessions       map[string]Session
	LdapUrl        string
	BaseDn         string
	FilterTemplate string
	Mutex          *sync.Mutex
}

type Session struct {
	id   string
	ldap *ldap.Conn
}

func (h Handler) dial() (*ldap.Conn, error) {
	if h.Verbose {
		fmt.Printf("Starting connection to %s\n", h.LdapUrl)
	}
	return ldap.DialURL(h.LdapUrl)
}

func (h Handler) getSession(conn *ldapserver.Conn) (Session, error) {
	id := connID(conn)

	h.Mutex.Lock()
	s, ok := h.Sessions[id] // use server connection if it exists
	h.Mutex.Unlock()

	if !ok { // open a new server connection if not
		l, err := h.dial()
		if err != nil {
			if h.Verbose {
				fmt.Printf("ERR: %s\n", err.Error())
			}
			return Session{}, err
		}
		// l.Debug = true
		s = Session{id: id, ldap: l}
		h.Mutex.Lock()
		h.Sessions[s.id] = s
		h.Mutex.Unlock()
	}
	return s, nil
}

func getFirstDNComponent(bindDN string) string {
	searchFilter, _, _ := strings.Cut(bindDN, ",")
	_, searchFilter, _ = strings.Cut(searchFilter, "=")
	return searchFilter	
}

func (h Handler) Bind(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.BindRequest) {
	result := ldapserver.ResultOperationsError.AsResult("Unknown Error")
	defer func(){
		if h.Verbose {
			fmt.Printf("Bind result: %+v\n", result)
		}
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, result)
	}()

	if !strings.HasSuffix(req.Name, h.AllowedBindDn) {
		result = ldapserver.ResultInsufficientAccessRights.AsResult("hey! that's trespassing")
		return
	}

	if req.Name == "" {
		if h.Verbose {
			log.Printf("Invalid bind with empty DN")
		}

		result = ldapserver.ResultInvalidCredentials.AsResult("Bind with empty DN is not allowed.")
		return
	}

	searchFilter := strings.ReplaceAll(h.FilterTemplate, "$1", getFirstDNComponent(req.Name))

	if h.Verbose {
		log.Printf("input bind-dn: %+v\n", req.Name)
		log.Printf("search-filter: %+v\n", searchFilter)
	}

	search := ldap.NewSearchRequest(
		h.BaseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 0, false,
		searchFilter,
		[]string{"dn"},
		nil,
	)

	s, err := h.getSession(conn)
	if err != nil {
		result = ldapserver.ResultOperationsError.AsResult("Upstream connection error")
		return
	}
	if h.Verbose {
		log.Printf("Performing search: %+v ", search)
	}

	sr, err := s.ldap.Search(search)
	if err != nil {
		result = ldapserver.ResultOperationsError.AsResult(fmt.Sprintf("error: %s", err))
		return
	}

	if len(sr.Entries) == 0 {
		result = ldapserver.ResultNoSuchObject.AsResult("Not found")
		return
	}

	bindSimplePw := req.Credentials.(string)
	for _, entry := range sr.Entries {
		newDn := entry.DN
		if h.Verbose {
			log.Printf("Search matched DN: %+v ", newDn)
		}
		if err := s.ldap.Bind(newDn, bindSimplePw); err != nil {
			if h.Verbose {
				log.Printf("Failed auth with %s, continuing\n", newDn)
			}
			continue
		}

		if h.Verbose {
			log.Printf("Auth succeeded with: %+v ", newDn)
		}
		result = ldapserver.ResultSuccess.AsResult("Success")
		return
	}

	if h.Verbose {
		log.Printf("Failed auth against all matched entries")
	}
	result = ldapserver.ResultInvalidCredentials.AsResult("Could not bind with the given password")
	return
}

func connID(conn *ldapserver.Conn) string {
	h := sha1.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}
