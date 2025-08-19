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

type ClientConfig struct {
	BindDN string
	BindPW string
}

type Handler struct {
	ldapserver.BaseHandler

	Sessions       map[string]Session
	LdapUri        string
	BaseDn         string
	FilterTemplate string
	Mutex          *sync.Mutex
}

type Session struct {
	id   string
	ldap *ldap.Conn
}

func (h Handler) dial() (*ldap.Conn, error) {
	fmt.Printf("Starting connection to %s\n", h.LdapUri)
	return ldap.DialURL(h.LdapUri)
}

func (h Handler) getSession(conn *ldapserver.Conn) (Session, error) {
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
		s = Session{id: id, ldap: l}
		h.Mutex.Lock()
		h.Sessions[s.id] = s
		h.Mutex.Unlock()
	}
	return s, nil
}

func (h Handler) Bind(conn *ldapserver.Conn, msg *ldapserver.Message, req *ldapserver.BindRequest) {
	bindDN := req.Name
	if bindDN == "" {
		log.Printf("Invalid bind with empty DN")

		conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, ldapserver.ResultInvalidCredentials.AsResult("Bind with empty DN is not allowed."))

		return
	}

	bindSimplePw := req.Credentials.(string)

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
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, ldapserver.ResultOperationsError.AsResult(""))

		return
	}
	log.Printf("Performing search: %+v ", search)

	sr, err := s.ldap.Search(search)
	if err != nil {
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, ldapserver.ResultOperationsError.AsResult(""))

		return
	}

	if len(sr.Entries) == 0 {
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, ldapserver.ResultNoSuchObject.AsResult(""))

		return
	}

	for _, entry := range sr.Entries {
		newDn := entry.DN
		log.Printf("Search matched DN: %+v ", newDn)

		if err := s.ldap.Bind(newDn, bindSimplePw); err != nil {
			log.Printf("Failed auth, continuing")
			continue
		}

		log.Printf("Auth succeeded!: %+v ", newDn)
		conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, ldapserver.ResultSuccess.AsResult(""))

		return
	}

	log.Printf("Failed auth against all matched entries")
	conn.SendResult(msg.MessageID, nil, ldapserver.TypeBindResponseOp, ldapserver.ResultInvalidCredentials.AsResult(""))

	return
}

func connID(conn *ldapserver.Conn) string {
	h := sha1.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}
