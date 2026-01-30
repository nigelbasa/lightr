package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type AuthMode string

const (
	AuthModeNative    AuthMode = "native"
	AuthModeOffloaded AuthMode = "offloaded"
)

type Organization struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	BillingTier string    `json:"billing_tier"`
	CreatedAt   time.Time `json:"created_at"`
}

type Domain struct {
	ID             uuid.UUID `json:"id"`
	OrgID          uuid.UUID `json:"org_id"`
	Name           string    `json:"name"`
	DKIMPrivateKey string    `json:"-"`
	DKIMSelector   string    `json:"dkim_selector"`
	WebhookURL     string    `json:"webhook_url,omitempty"`
	IsVerified     bool      `json:"is_verified"`
	CreatedAt      time.Time `json:"created_at"`
}

type Account struct {
	ID            uuid.UUID  `json:"id"`
	OrgID         uuid.UUID  `json:"org_id"`
	DomainID      uuid.UUID  `json:"domain_id"`
	Email         string     `json:"email"`
	LocalPart     string     `json:"local_part"`
	DisplayName   string     `json:"display_name,omitempty"`
	AuthMode      AuthMode   `json:"auth_mode"`
	PasswordHash  string     `json:"-"`
	ExternalID    string     `json:"external_id,omitempty"`   // ID from external auth provider
	ProviderID    *uuid.UUID `json:"provider_id,omitempty"`   // Auth provider used
	StorageQuota  int64      `json:"storage_quota"`
	QuotaBytes    int64      `json:"quota_bytes"`
	UsedBytes     int64      `json:"used_bytes"`
	Status        string     `json:"status"`                  // active, suspended, disabled
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type Message struct {
	ID          uuid.UUID  `json:"id"`
	AccountID   uuid.UUID  `json:"account_id"`
	Folder      string     `json:"folder"`
	SizeBytes   int64      `json:"size_bytes"`
	StoragePath string     `json:"-"`
	Subject     string     `json:"subject"`
	From        string     `json:"from"`
	To          string     `json:"to"`
	ReceivedAt  time.Time  `json:"received_at"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

type TrackingEvent struct {
	ID        uuid.UUID `json:"id"`
	MessageID uuid.UUID `json:"message_id"`
	EventType string    `json:"event_type"` // open, click
	LinkURL   string    `json:"link_url,omitempty"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthService & Auth Hooks
type AuthService interface {
	Authenticate(ctx context.Context, username, password string) (*Account, error)
}

type AuthOffloader interface {
	OffloadAuth(ctx context.Context, username, password string) (*Account, error)
}

// Repository Interfaces

type AccountRepository interface {
	CreateAccount(acc *Account) error
	GetAccountByID(id uuid.UUID) (*Account, error)
	GetAccountByEmail(email string) (*Account, error)
	GetAccountByLocalPart(domainID uuid.UUID, localPart string) (*Account, error)
	UpdateAccount(acc *Account) error
	DeleteAccount(id uuid.UUID) error
}

type DomainRepository interface {
	CreateDomain(dom *Domain) error
	GetDomainByID(id uuid.UUID) (*Domain, error)
	GetDomainByName(name string) (*Domain, error)
	ListDomainsByOrg(orgID uuid.UUID) ([]*Domain, error)
}

type MessageRepository interface {
	CreateMessage(msg *Message) error
	GetMessageByID(id uuid.UUID) (*Message, error)
	ListByAccount(accountID uuid.UUID, folder string) ([]*Message, error)
	UpdateMessage(msg *Message) error
}

type BlobStorage interface {
	Put(path string, data []byte) error
	Get(path string) ([]byte, error)
	Delete(path string) error
}

type OrganizationRepository interface {
	CreateOrg(org *Organization) error
	GetOrgByID(id uuid.UUID) (*Organization, error)
	ListOrgs() ([]*Organization, error)
}

type TrackingEventRepository interface {
	CreateTrackingEvent(event *TrackingEvent) error
	GetTrackingEventsByMessage(messageID uuid.UUID) ([]*TrackingEvent, error)
}
