package alias

import (
	"strings"

	"github.com/google/uuid"
	"github.com/nigelbasa/lightr/internal/domain"
)

// Resolver resolves email addresses to their final destinations
type Resolver struct {
	aliasRepo  Repository
	domainRepo domain.DomainRepository
	maxDepth   int // Maximum alias chain depth to prevent loops
}

// NewResolver creates a new alias resolver
func NewResolver(aliasRepo Repository, domainRepo domain.DomainRepository) *Resolver {
	return &Resolver{
		aliasRepo:  aliasRepo,
		domainRepo: domainRepo,
		maxDepth:   10,
	}
}

// ResolveResult contains the resolution result
type ResolveResult struct {
	// Original is the original address that was looked up
	Original string
	// Resolved contains the final destination addresses
	Resolved []string
	// IsAlias indicates if an alias was matched
	IsAlias bool
	// AliasID is the ID of the matched alias (if any)
	AliasID *uuid.UUID
	// AliasType is the type of alias matched
	AliasType AliasType
}

// Resolve resolves an email address through aliases
// Returns the resolved destinations or the original address if no alias
func (r *Resolver) Resolve(email string) (*ResolveResult, error) {
	result := &ResolveResult{
		Original: email,
		Resolved: []string{email},
		IsAlias:  false,
	}

	// Parse the email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return result, nil
	}
	localPart := strings.ToLower(parts[0])
	domainName := strings.ToLower(parts[1])

	// Find domain
	dom, err := r.domainRepo.GetDomainByName(domainName)
	if err != nil || dom == nil {
		// Not our domain, return original
		return result, nil
	}

	// Look up alias
	alias, err := r.aliasRepo.FindByAddress(localPart, dom.ID.String())
	if err != nil || alias == nil {
		return result, nil
	}

	// Found an alias
	result.IsAlias = true
	result.AliasID = &alias.ID
	result.AliasType = alias.Type

	// Resolve destinations (may be aliases themselves)
	seen := make(map[string]bool)
	seen[email] = true

	resolved, err := r.resolveDestinations(alias.Destinations, seen, 0)
	if err != nil {
		return nil, err
	}

	result.Resolved = resolved
	return result, nil
}

func (r *Resolver) resolveDestinations(destinations []string, seen map[string]bool, depth int) ([]string, error) {
	if depth >= r.maxDepth {
		return destinations, nil // Max depth reached, return as-is
	}

	var resolved []string

	for _, dest := range destinations {
		dest = strings.TrimSpace(dest)
		if dest == "" {
			continue
		}

		// Skip if we've seen this address (loop prevention)
		if seen[dest] {
			continue
		}
		seen[dest] = true

		// Try to resolve this destination as well
		parts := strings.Split(dest, "@")
		if len(parts) != 2 {
			resolved = append(resolved, dest)
			continue
		}

		localPart := strings.ToLower(parts[0])
		domainName := strings.ToLower(parts[1])

		// Check if this is one of our domains
		dom, err := r.domainRepo.GetDomainByName(domainName)
		if err != nil || dom == nil {
			// External address, keep as-is
			resolved = append(resolved, dest)
			continue
		}

		// Look up alias for this destination
		alias, err := r.aliasRepo.FindByAddress(localPart, dom.ID.String())
		if err != nil || alias == nil {
			// No alias, keep as-is
			resolved = append(resolved, dest)
			continue
		}

		// Recursively resolve
		subResolved, err := r.resolveDestinations(alias.Destinations, seen, depth+1)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, subResolved...)
	}

	return resolved, nil
}

// IsLocalAddress checks if an address belongs to one of our domains
func (r *Resolver) IsLocalAddress(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domainName := strings.ToLower(parts[1])

	dom, err := r.domainRepo.GetDomainByName(domainName)
	return err == nil && dom != nil
}
