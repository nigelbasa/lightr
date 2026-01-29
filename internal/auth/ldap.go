package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPOffloader implements Offloader for LDAP/Active Directory auth
type LDAPOffloader struct {
	config    *ProviderConfig
	ldapCfg   *LDAPConfig
	conn      *ldap.Conn
	connected bool
}

// NewLDAPOffloader creates a new LDAP offloader
func NewLDAPOffloader(config *ProviderConfig) (*LDAPOffloader, error) {
	var ldapCfg LDAPConfig
	if err := json.Unmarshal(config.Config, &ldapCfg); err != nil {
		return nil, fmt.Errorf("invalid LDAP config: %w", err)
	}

	// Set defaults
	if ldapCfg.Port == 0 {
		if ldapCfg.UseTLS {
			ldapCfg.Port = 636
		} else {
			ldapCfg.Port = 389
		}
	}
	if ldapCfg.Timeout == 0 {
		ldapCfg.Timeout = 10
	}
	if ldapCfg.UserFilter == "" {
		ldapCfg.UserFilter = "(uid=%s)"
	}
	if ldapCfg.EmailAttr == "" {
		ldapCfg.EmailAttr = "mail"
	}
	if ldapCfg.DisplayNameAttr == "" {
		ldapCfg.DisplayNameAttr = "displayName"
	}
	if ldapCfg.GroupAttr == "" {
		ldapCfg.GroupAttr = "memberOf"
	}

	offloader := &LDAPOffloader{
		config:  config,
		ldapCfg: &ldapCfg,
	}

	return offloader, nil
}

func (l *LDAPOffloader) connect() error {
	if l.connected && l.conn != nil {
		// Test connection
		if err := l.conn.Bind(l.ldapCfg.BindDN, l.ldapCfg.BindPassword); err == nil {
			return nil
		}
		l.conn.Close()
	}

	addr := fmt.Sprintf("%s:%d", l.ldapCfg.Host, l.ldapCfg.Port)

	var conn *ldap.Conn
	var err error

	tlsConfig := &tls.Config{
		InsecureSkipVerify: l.ldapCfg.SkipVerify,
		ServerName:         l.ldapCfg.Host,
	}

	if l.ldapCfg.UseTLS {
		conn, err = ldap.DialTLS("tcp", addr, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", addr)
		if err == nil && l.ldapCfg.StartTLS {
			err = conn.StartTLS(tlsConfig)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	conn.SetTimeout(time.Duration(l.ldapCfg.Timeout) * time.Second)
	l.conn = conn
	l.connected = true

	return nil
}

func (l *LDAPOffloader) Authenticate(ctx context.Context, username, password string) (*OffloadResult, error) {
	if err := l.connect(); err != nil {
		return nil, err
	}

	result := &OffloadResult{
		Success: false,
	}

	// Bind with service account to search
	if err := l.conn.Bind(l.ldapCfg.BindDN, l.ldapCfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service bind failed: %w", err)
	}

	// Search for user
	searchFilter := fmt.Sprintf(l.ldapCfg.UserFilter, ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		l.ldapCfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, l.ldapCfg.Timeout, false,
		searchFilter,
		[]string{"dn", l.ldapCfg.EmailAttr, l.ldapCfg.DisplayNameAttr, l.ldapCfg.GroupAttr},
		nil,
	)

	sr, err := l.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		result.Error = "user not found"
		return result, nil
	}

	if len(sr.Entries) > 1 {
		result.Error = "multiple users found"
		return result, nil
	}

	userDN := sr.Entries[0].DN
	entry := sr.Entries[0]

	// Attempt bind with user credentials
	if err := l.conn.Bind(userDN, password); err != nil {
		result.Error = "invalid credentials"
		return result, nil
	}

	// Authentication successful
	result.Success = true
	result.UserID = userDN
	result.Email = entry.GetAttributeValue(l.ldapCfg.EmailAttr)
	result.DisplayName = entry.GetAttributeValue(l.ldapCfg.DisplayNameAttr)

	// If email not found, try to construct from username
	if result.Email == "" {
		if strings.Contains(username, "@") {
			result.Email = username
		}
	}

	// Get groups
	groups := entry.GetAttributeValues(l.ldapCfg.GroupAttr)
	for _, group := range groups {
		// Extract CN from group DN
		cn := extractCN(group)
		if cn != "" {
			result.Groups = append(result.Groups, cn)
		}
	}

	// Rebind as service account for future operations
	l.conn.Bind(l.ldapCfg.BindDN, l.ldapCfg.BindPassword)

	return result, nil
}

func (l *LDAPOffloader) ValidateToken(ctx context.Context, token string) (*OffloadResult, error) {
	return nil, errors.New("token validation not supported for LDAP provider")
}

func (l *LDAPOffloader) RefreshToken(ctx context.Context, refreshToken string) (*OffloadResult, error) {
	return nil, errors.New("token refresh not supported for LDAP provider")
}

func (l *LDAPOffloader) GetProviderType() AuthProvider {
	return ProviderLDAP
}

func (l *LDAPOffloader) Close() error {
	if l.conn != nil {
		l.conn.Close()
		l.conn = nil
		l.connected = false
	}
	return nil
}

// GetUserGroups retrieves groups for a user DN
func (l *LDAPOffloader) GetUserGroups(ctx context.Context, userDN string) ([]string, error) {
	if err := l.connect(); err != nil {
		return nil, err
	}

	if err := l.conn.Bind(l.ldapCfg.BindDN, l.ldapCfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service bind failed: %w", err)
	}

	baseDN := l.ldapCfg.GroupBaseDN
	if baseDN == "" {
		baseDN = l.ldapCfg.BaseDN
	}

	groupFilter := l.ldapCfg.GroupFilter
	if groupFilter == "" {
		groupFilter = "(member=%s)"
	}
	searchFilter := fmt.Sprintf(groupFilter, ldap.EscapeFilter(userDN))

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, l.ldapCfg.Timeout, false,
		searchFilter,
		[]string{"cn"},
		nil,
	)

	sr, err := l.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("group search failed: %w", err)
	}

	var groups []string
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			groups = append(groups, cn)
		}
	}

	return groups, nil
}

// SearchUsers searches for users matching a query
func (l *LDAPOffloader) SearchUsers(ctx context.Context, query string, limit int) ([]LDAPUser, error) {
	if err := l.connect(); err != nil {
		return nil, err
	}

	if err := l.conn.Bind(l.ldapCfg.BindDN, l.ldapCfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service bind failed: %w", err)
	}

	if limit == 0 {
		limit = 100
	}

	// Search with wildcard
	searchFilter := fmt.Sprintf("(&(objectClass=person)(|(cn=*%s*)(mail=*%s*)(sAMAccountName=*%s*)))",
		ldap.EscapeFilter(query), ldap.EscapeFilter(query), ldap.EscapeFilter(query))

	searchRequest := ldap.NewSearchRequest(
		l.ldapCfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, l.ldapCfg.Timeout, false,
		searchFilter,
		[]string{"dn", "cn", l.ldapCfg.EmailAttr, l.ldapCfg.DisplayNameAttr},
		nil,
	)

	sr, err := l.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}

	var users []LDAPUser
	for _, entry := range sr.Entries {
		users = append(users, LDAPUser{
			DN:          entry.DN,
			CN:          entry.GetAttributeValue("cn"),
			Email:       entry.GetAttributeValue(l.ldapCfg.EmailAttr),
			DisplayName: entry.GetAttributeValue(l.ldapCfg.DisplayNameAttr),
		})
	}

	return users, nil
}

// LDAPUser represents a user from LDAP
type LDAPUser struct {
	DN          string `json:"dn"`
	CN          string `json:"cn"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// Helper to extract CN from DN
func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "cn=") {
			return part[3:]
		}
	}
	return ""
}

// ActiveDirectoryConfig extends LDAPConfig with AD-specific settings
type ActiveDirectoryConfig struct {
	LDAPConfig
	Domain         string `json:"domain"`           // AD domain (e.g., "corp.example.com")
	UseUPN         bool   `json:"use_upn"`          // Use user@domain format
	NestedGroups   bool   `json:"nested_groups"`    // Resolve nested group memberships
}

// NewActiveDirectoryOffloader creates an AD-optimized offloader
func NewActiveDirectoryOffloader(config *ProviderConfig) (*LDAPOffloader, error) {
	var adCfg ActiveDirectoryConfig
	if err := json.Unmarshal(config.Config, &adCfg); err != nil {
		return nil, fmt.Errorf("invalid AD config: %w", err)
	}

	// Set AD-specific defaults
	if adCfg.UserFilter == "" {
		if adCfg.UseUPN {
			adCfg.UserFilter = "(userPrincipalName=%s)"
		} else {
			adCfg.UserFilter = "(sAMAccountName=%s)"
		}
	}
	if adCfg.EmailAttr == "" {
		adCfg.EmailAttr = "mail"
	}
	if adCfg.DisplayNameAttr == "" {
		adCfg.DisplayNameAttr = "displayName"
	}
	if adCfg.GroupAttr == "" {
		adCfg.GroupAttr = "memberOf"
	}

	// Create standard LDAP offloader with AD config
	ldapCfgJSON, _ := json.Marshal(adCfg.LDAPConfig)
	config.Config = ldapCfgJSON

	return NewLDAPOffloader(config)
}
