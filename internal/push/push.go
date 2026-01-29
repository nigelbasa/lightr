package push

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Provider represents a push notification provider
type Provider string

const (
	ProviderAPNS Provider = "apns" // Apple Push Notification Service
	ProviderFCM  Provider = "fcm"  // Firebase Cloud Messaging
	ProviderWebPush Provider = "webpush" // Web Push (VAPID)
)

// NotificationType represents the type of notification
type NotificationType string

const (
	TypeNewEmail     NotificationType = "new_email"
	TypeCalendar     NotificationType = "calendar"
	TypeReminder     NotificationType = "reminder"
	TypeSync         NotificationType = "sync"
	TypeSecurity     NotificationType = "security"
	TypeSystem       NotificationType = "system"
)

// Priority represents notification priority
type Priority string

const (
	PriorityLow    Priority = "low"
	PriorityNormal Priority = "normal"
	PriorityHigh   Priority = "high"
)

// Device represents a registered push device
type Device struct {
	ID          uuid.UUID `json:"id"`
	AccountID   uuid.UUID `json:"account_id"`
	OrgID       uuid.UUID `json:"org_id"`
	
	// Device info
	Provider    Provider  `json:"provider"`
	Token       string    `json:"token"`         // Device token or registration ID
	DeviceID    string    `json:"device_id"`     // Unique device identifier
	DeviceName  string    `json:"device_name,omitempty"`
	DeviceModel string    `json:"device_model,omitempty"`
	OSVersion   string    `json:"os_version,omitempty"`
	AppVersion  string    `json:"app_version,omitempty"`
	
	// Web Push specific
	Endpoint    string    `json:"endpoint,omitempty"`
	P256dh      string    `json:"p256dh,omitempty"`      // Public key
	Auth        string    `json:"auth,omitempty"`        // Auth secret
	
	// Settings
	Enabled     bool      `json:"enabled"`
	BadgeCount  int       `json:"badge_count"`
	
	// Preferences (what notifications to receive)
	Preferences *DevicePreferences `json:"preferences,omitempty"`
	
	// Metadata
	LastActive  time.Time `json:"last_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DevicePreferences configures what notifications a device receives
type DevicePreferences struct {
	NewEmail       bool   `json:"new_email"`
	Calendar       bool   `json:"calendar"`
	Reminders      bool   `json:"reminders"`
	Security       bool   `json:"security"`
	System         bool   `json:"system"`
	
	// Email specific
	OnlyPriority   bool   `json:"only_priority"`     // Only high priority emails
	OnlyContacts   bool   `json:"only_contacts"`     // Only from contacts
	MutedFolders   []string `json:"muted_folders,omitempty"` // Don't notify for these folders
	MutedSenders   []string `json:"muted_senders,omitempty"` // Don't notify for these senders
	
	// Quiet hours
	QuietStart     string `json:"quiet_start,omitempty"` // "22:00"
	QuietEnd       string `json:"quiet_end,omitempty"`   // "07:00"
	QuietDays      []int  `json:"quiet_days,omitempty"`  // 0=Sunday, 6=Saturday
}

// Notification represents a push notification
type Notification struct {
	ID          uuid.UUID        `json:"id"`
	AccountID   uuid.UUID        `json:"account_id"`
	DeviceID    uuid.UUID        `json:"device_id"`
	
	Type        NotificationType `json:"type"`
	Priority    Priority         `json:"priority"`
	
	// Content
	Title       string           `json:"title"`
	Body        string           `json:"body"`
	Subtitle    string           `json:"subtitle,omitempty"`
	ImageURL    string           `json:"image_url,omitempty"`
	
	// Actions
	Actions     []Action         `json:"actions,omitempty"`
	
	// Data payload
	Data        map[string]string `json:"data,omitempty"`
	
	// iOS specific
	Badge       *int             `json:"badge,omitempty"`
	Sound       string           `json:"sound,omitempty"`
	Category    string           `json:"category,omitempty"`
	ThreadID    string           `json:"thread_id,omitempty"`
	
	// Android specific
	ChannelID   string           `json:"channel_id,omitempty"`
	Tag         string           `json:"tag,omitempty"`
	CollapseKey string           `json:"collapse_key,omitempty"`
	TTL         int              `json:"ttl,omitempty"` // Time to live in seconds
	
	// Status
	Status      string           `json:"status"` // "pending", "sent", "delivered", "failed"
	SentAt      *time.Time       `json:"sent_at,omitempty"`
	DeliveredAt *time.Time       `json:"delivered_at,omitempty"`
	FailedAt    *time.Time       `json:"failed_at,omitempty"`
	Error       string           `json:"error,omitempty"`
	
	CreatedAt   time.Time        `json:"created_at"`
}

// Action represents a notification action button
type Action struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Icon  string `json:"icon,omitempty"`
	URL   string `json:"url,omitempty"`
}

// EmailNotificationData contains data for new email notifications
type EmailNotificationData struct {
	MessageID   uuid.UUID `json:"message_id"`
	From        string    `json:"from"`
	FromName    string    `json:"from_name,omitempty"`
	Subject     string    `json:"subject"`
	Preview     string    `json:"preview"`
	Folder      string    `json:"folder"`
	HasAttachment bool    `json:"has_attachment"`
	IsPriority  bool      `json:"is_priority"`
	ThreadID    string    `json:"thread_id,omitempty"`
}

// Service handles push notifications
type Service struct {
	mu       sync.RWMutex
	repo     Repository
	apns     APNSClient
	fcm      FCMClient
	webpush  WebPushClient
	logger   Logger
	queue    chan *sendJob
	stopCh   chan struct{}
	workers  int
	running  bool
}

type sendJob struct {
	notification *Notification
	device       *Device
}

// APNSClient interface for APNS
type APNSClient interface {
	Send(ctx context.Context, token string, payload *APNSPayload) error
}

// APNSPayload represents an APNS payload
type APNSPayload struct {
	Alert       *APNSAlert        `json:"alert,omitempty"`
	Badge       *int              `json:"badge,omitempty"`
	Sound       string            `json:"sound,omitempty"`
	Category    string            `json:"category,omitempty"`
	ThreadID    string            `json:"thread-id,omitempty"`
	ContentAvailable int          `json:"content-available,omitempty"`
	MutableContent int            `json:"mutable-content,omitempty"`
	Data        map[string]string `json:"-"`
}

// APNSAlert represents APNS alert content
type APNSAlert struct {
	Title    string `json:"title,omitempty"`
	Subtitle string `json:"subtitle,omitempty"`
	Body     string `json:"body,omitempty"`
}

// FCMClient interface for Firebase Cloud Messaging
type FCMClient interface {
	Send(ctx context.Context, token string, message *FCMMessage) error
}

// FCMMessage represents an FCM message
type FCMMessage struct {
	Notification *FCMNotification  `json:"notification,omitempty"`
	Data         map[string]string `json:"data,omitempty"`
	Android      *FCMAndroid       `json:"android,omitempty"`
	Webpush      *FCMWebPush       `json:"webpush,omitempty"`
}

// FCMNotification represents FCM notification content
type FCMNotification struct {
	Title    string `json:"title,omitempty"`
	Body     string `json:"body,omitempty"`
	ImageURL string `json:"image,omitempty"`
}

// FCMAndroid contains Android-specific options
type FCMAndroid struct {
	Priority     string            `json:"priority,omitempty"`
	TTL          string            `json:"ttl,omitempty"`
	CollapseKey  string            `json:"collapse_key,omitempty"`
	ChannelID    string            `json:"channel_id,omitempty"`
	Tag          string            `json:"tag,omitempty"`
	Notification *FCMNotification  `json:"notification,omitempty"`
	Data         map[string]string `json:"data,omitempty"`
}

// FCMWebPush contains web push options
type FCMWebPush struct {
	Headers      map[string]string `json:"headers,omitempty"`
	Notification map[string]string `json:"notification,omitempty"`
}

// WebPushClient interface for Web Push
type WebPushClient interface {
	Send(ctx context.Context, subscription *WebPushSubscription, payload []byte) error
}

// WebPushSubscription represents a web push subscription
type WebPushSubscription struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// Repository interface
type Repository interface {
	// Devices
	SaveDevice(ctx context.Context, device *Device) error
	GetDevice(ctx context.Context, id uuid.UUID) (*Device, error)
	GetDeviceByToken(ctx context.Context, token string) (*Device, error)
	GetDevicesForAccount(ctx context.Context, accountID uuid.UUID) ([]*Device, error)
	GetActiveDevices(ctx context.Context, accountID uuid.UUID) ([]*Device, error)
	UpdateDevice(ctx context.Context, device *Device) error
	DeleteDevice(ctx context.Context, id uuid.UUID) error
	
	// Notifications
	SaveNotification(ctx context.Context, notification *Notification) error
	GetNotification(ctx context.Context, id uuid.UUID) (*Notification, error)
	GetPendingNotifications(ctx context.Context, limit int) ([]*Notification, error)
	UpdateNotificationStatus(ctx context.Context, id uuid.UUID, status string, err string) error
	GetNotificationHistory(ctx context.Context, accountID uuid.UUID, limit int) ([]*Notification, error)
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewService creates a new push notification service
func NewService(repo Repository, apns APNSClient, fcm FCMClient, webpush WebPushClient, logger Logger, workers int) *Service {
	if workers <= 0 {
		workers = 4
	}
	return &Service{
		repo:    repo,
		apns:    apns,
		fcm:     fcm,
		webpush: webpush,
		logger:  logger,
		queue:   make(chan *sendJob, 1000),
		stopCh:  make(chan struct{}),
		workers: workers,
	}
}

// Start starts the notification workers
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	for i := 0; i < s.workers; i++ {
		go s.worker(ctx, i)
	}

	s.logger.Info("push notification service started", "workers", s.workers)
	return nil
}

// Stop stops the service
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.running = false
	s.logger.Info("push notification service stopped")
}

func (s *Service) worker(ctx context.Context, id int) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case job := <-s.queue:
			s.sendNotification(ctx, job.notification, job.device)
		}
	}
}

// Device Registration

// RegisterDevice registers a new device for push notifications
func (s *Service) RegisterDevice(ctx context.Context, device *Device) error {
	// Check if device already registered
	existing, err := s.repo.GetDeviceByToken(ctx, device.Token)
	if err == nil && existing != nil {
		// Update existing device
		existing.AccountID = device.AccountID
		existing.DeviceName = device.DeviceName
		existing.DeviceModel = device.DeviceModel
		existing.OSVersion = device.OSVersion
		existing.AppVersion = device.AppVersion
		existing.Enabled = true
		existing.LastActive = time.Now()
		existing.UpdatedAt = time.Now()
		return s.repo.UpdateDevice(ctx, existing)
	}

	device.ID = uuid.New()
	device.Enabled = true
	device.LastActive = time.Now()
	device.CreatedAt = time.Now()
	device.UpdatedAt = time.Now()

	if device.Preferences == nil {
		device.Preferences = &DevicePreferences{
			NewEmail:  true,
			Calendar:  true,
			Reminders: true,
			Security:  true,
			System:    true,
		}
	}

	if err := s.repo.SaveDevice(ctx, device); err != nil {
		return err
	}

	s.logger.Info("registered device", "id", device.ID, "provider", device.Provider)
	return nil
}

// UnregisterDevice removes a device from push notifications
func (s *Service) UnregisterDevice(ctx context.Context, deviceID uuid.UUID) error {
	return s.repo.DeleteDevice(ctx, deviceID)
}

// UpdateDeviceToken updates a device's push token
func (s *Service) UpdateDeviceToken(ctx context.Context, deviceID uuid.UUID, newToken string) error {
	device, err := s.repo.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}

	device.Token = newToken
	device.UpdatedAt = time.Now()
	return s.repo.UpdateDevice(ctx, device)
}

// UpdateDevicePreferences updates notification preferences
func (s *Service) UpdateDevicePreferences(ctx context.Context, deviceID uuid.UUID, prefs *DevicePreferences) error {
	device, err := s.repo.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}

	device.Preferences = prefs
	device.UpdatedAt = time.Now()
	return s.repo.UpdateDevice(ctx, device)
}

// Sending Notifications

// SendNewEmailNotification sends a notification for a new email
func (s *Service) SendNewEmailNotification(ctx context.Context, accountID uuid.UUID, emailData *EmailNotificationData) error {
	devices, err := s.repo.GetActiveDevices(ctx, accountID)
	if err != nil {
		return err
	}

	for _, device := range devices {
		if !s.shouldNotify(device, emailData) {
			continue
		}

		notification := &Notification{
			ID:        uuid.New(),
			AccountID: accountID,
			DeviceID:  device.ID,
			Type:      TypeNewEmail,
			Priority:  PriorityNormal,
			Title:     emailData.FromName,
			Body:      emailData.Subject,
			Subtitle:  emailData.Preview,
			Data: map[string]string{
				"message_id": emailData.MessageID.String(),
				"folder":     emailData.Folder,
				"type":       string(TypeNewEmail),
			},
			Sound:     "default",
			ThreadID:  emailData.ThreadID,
			Category:  "EMAIL",
			Status:    "pending",
			CreatedAt: time.Now(),
		}

		if emailData.IsPriority {
			notification.Priority = PriorityHigh
		}

		// Set badge count
		badge := device.BadgeCount + 1
		notification.Badge = &badge

		// Add actions
		notification.Actions = []Action{
			{ID: "reply", Title: "Reply"},
			{ID: "archive", Title: "Archive"},
		}

		if err := s.repo.SaveNotification(ctx, notification); err != nil {
			s.logger.Error("failed to save notification", "error", err)
			continue
		}

		// Queue for sending
		select {
		case s.queue <- &sendJob{notification: notification, device: device}:
		default:
			s.logger.Error("notification queue full")
		}
	}

	return nil
}

// SendNotification sends a generic notification
func (s *Service) SendNotification(ctx context.Context, notification *Notification) error {
	device, err := s.repo.GetDevice(ctx, notification.DeviceID)
	if err != nil {
		return err
	}

	notification.ID = uuid.New()
	notification.Status = "pending"
	notification.CreatedAt = time.Now()

	if err := s.repo.SaveNotification(ctx, notification); err != nil {
		return err
	}

	// Queue for sending
	select {
	case s.queue <- &sendJob{notification: notification, device: device}:
	default:
		return fmt.Errorf("notification queue full")
	}

	return nil
}

// SendBulkNotification sends a notification to all devices for an account
func (s *Service) SendBulkNotification(ctx context.Context, accountID uuid.UUID, notificationType NotificationType, title, body string, data map[string]string) error {
	devices, err := s.repo.GetActiveDevices(ctx, accountID)
	if err != nil {
		return err
	}

	for _, device := range devices {
		notification := &Notification{
			ID:        uuid.New(),
			AccountID: accountID,
			DeviceID:  device.ID,
			Type:      notificationType,
			Priority:  PriorityNormal,
			Title:     title,
			Body:      body,
			Data:      data,
			Sound:     "default",
			Status:    "pending",
			CreatedAt: time.Now(),
		}

		if err := s.repo.SaveNotification(ctx, notification); err != nil {
			s.logger.Error("failed to save notification", "error", err)
			continue
		}

		select {
		case s.queue <- &sendJob{notification: notification, device: device}:
		default:
			s.logger.Error("notification queue full")
		}
	}

	return nil
}

func (s *Service) shouldNotify(device *Device, emailData *EmailNotificationData) bool {
	if !device.Enabled {
		return false
	}

	prefs := device.Preferences
	if prefs == nil {
		return true
	}

	if !prefs.NewEmail {
		return false
	}

	// Check priority filter
	if prefs.OnlyPriority && !emailData.IsPriority {
		return false
	}

	// Check muted folders
	for _, folder := range prefs.MutedFolders {
		if folder == emailData.Folder {
			return false
		}
	}

	// Check muted senders
	for _, sender := range prefs.MutedSenders {
		if sender == emailData.From {
			return false
		}
	}

	// Check quiet hours
	if prefs.QuietStart != "" && prefs.QuietEnd != "" {
		if isQuietTime(prefs.QuietStart, prefs.QuietEnd, prefs.QuietDays) {
			return false
		}
	}

	return true
}

func (s *Service) sendNotification(ctx context.Context, notification *Notification, device *Device) {
	var err error

	switch device.Provider {
	case ProviderAPNS:
		err = s.sendAPNS(ctx, notification, device)
	case ProviderFCM:
		err = s.sendFCM(ctx, notification, device)
	case ProviderWebPush:
		err = s.sendWebPush(ctx, notification, device)
	default:
		err = fmt.Errorf("unknown provider: %s", device.Provider)
	}

	if err != nil {
		now := time.Now()
		notification.Status = "failed"
		notification.FailedAt = &now
		notification.Error = err.Error()
		s.repo.UpdateNotificationStatus(ctx, notification.ID, "failed", err.Error())
		s.logger.Error("failed to send notification", "id", notification.ID, "error", err)
		
		// Handle invalid token
		if isInvalidTokenError(err) {
			s.handleInvalidToken(ctx, device)
		}
	} else {
		now := time.Now()
		notification.Status = "sent"
		notification.SentAt = &now
		s.repo.UpdateNotificationStatus(ctx, notification.ID, "sent", "")
		
		// Update device badge count
		if notification.Badge != nil {
			device.BadgeCount = *notification.Badge
			s.repo.UpdateDevice(ctx, device)
		}
		
		s.logger.Debug("sent notification", "id", notification.ID, "device", device.ID)
	}
}

func (s *Service) sendAPNS(ctx context.Context, notification *Notification, device *Device) error {
	if s.apns == nil {
		return fmt.Errorf("APNS client not configured")
	}

	payload := &APNSPayload{
		Alert: &APNSAlert{
			Title:    notification.Title,
			Subtitle: notification.Subtitle,
			Body:     notification.Body,
		},
		Badge:    notification.Badge,
		Sound:    notification.Sound,
		Category: notification.Category,
		ThreadID: notification.ThreadID,
		Data:     notification.Data,
	}

	return s.apns.Send(ctx, device.Token, payload)
}

func (s *Service) sendFCM(ctx context.Context, notification *Notification, device *Device) error {
	if s.fcm == nil {
		return fmt.Errorf("FCM client not configured")
	}

	message := &FCMMessage{
		Notification: &FCMNotification{
			Title:    notification.Title,
			Body:     notification.Body,
			ImageURL: notification.ImageURL,
		},
		Data: notification.Data,
		Android: &FCMAndroid{
			Priority:    string(notification.Priority),
			CollapseKey: notification.CollapseKey,
			ChannelID:   notification.ChannelID,
			Tag:         notification.Tag,
		},
	}

	if notification.TTL > 0 {
		message.Android.TTL = fmt.Sprintf("%ds", notification.TTL)
	}

	return s.fcm.Send(ctx, device.Token, message)
}

func (s *Service) sendWebPush(ctx context.Context, notification *Notification, device *Device) error {
	if s.webpush == nil {
		return fmt.Errorf("WebPush client not configured")
	}

	subscription := &WebPushSubscription{
		Endpoint: device.Endpoint,
	}
	subscription.Keys.P256dh = device.P256dh
	subscription.Keys.Auth = device.Auth

	payload := map[string]interface{}{
		"title": notification.Title,
		"body":  notification.Body,
		"icon":  notification.ImageURL,
		"data":  notification.Data,
	}

	if len(notification.Actions) > 0 {
		payload["actions"] = notification.Actions
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return s.webpush.Send(ctx, subscription, payloadBytes)
}

func (s *Service) handleInvalidToken(ctx context.Context, device *Device) {
	device.Enabled = false
	device.UpdatedAt = time.Now()
	s.repo.UpdateDevice(ctx, device)
	s.logger.Info("disabled device with invalid token", "id", device.ID)
}

func isInvalidTokenError(err error) bool {
	// Check for common invalid token errors
	errStr := err.Error()
	return contains(errStr, "InvalidToken") ||
		contains(errStr, "NotRegistered") ||
		contains(errStr, "Unregistered") ||
		contains(errStr, "BadDeviceToken")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Badge Management

// ResetBadgeCount resets the badge count for a device
func (s *Service) ResetBadgeCount(ctx context.Context, deviceID uuid.UUID) error {
	device, err := s.repo.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}

	device.BadgeCount = 0
	device.UpdatedAt = time.Now()
	return s.repo.UpdateDevice(ctx, device)
}

// IncrementBadgeCount increments the badge count
func (s *Service) IncrementBadgeCount(ctx context.Context, deviceID uuid.UUID, delta int) error {
	device, err := s.repo.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}

	device.BadgeCount += delta
	if device.BadgeCount < 0 {
		device.BadgeCount = 0
	}
	device.UpdatedAt = time.Now()
	return s.repo.UpdateDevice(ctx, device)
}

// Quiet Hours Helper
func isQuietTime(start, end string, quietDays []int) bool {
	now := time.Now()
	
	// Check day
	if len(quietDays) > 0 {
		today := int(now.Weekday())
		isQuietDay := false
		for _, d := range quietDays {
			if d == today {
				isQuietDay = true
				break
			}
		}
		if !isQuietDay {
			return false
		}
	}

	// Parse times
	startTime, err1 := time.Parse("15:04", start)
	endTime, err2 := time.Parse("15:04", end)
	if err1 != nil || err2 != nil {
		return false
	}

	currentTime := time.Date(0, 1, 1, now.Hour(), now.Minute(), 0, 0, time.UTC)
	startTime = time.Date(0, 1, 1, startTime.Hour(), startTime.Minute(), 0, 0, time.UTC)
	endTime = time.Date(0, 1, 1, endTime.Hour(), endTime.Minute(), 0, 0, time.UTC)

	// Handle overnight quiet hours
	if startTime.After(endTime) {
		return currentTime.After(startTime) || currentTime.Before(endTime)
	}

	return currentTime.After(startTime) && currentTime.Before(endTime)
}

// Mock implementations for testing

// MockAPNSClient is a mock APNS client
type MockAPNSClient struct {
	SendFunc func(ctx context.Context, token string, payload *APNSPayload) error
}

func (m *MockAPNSClient) Send(ctx context.Context, token string, payload *APNSPayload) error {
	if m.SendFunc != nil {
		return m.SendFunc(ctx, token, payload)
	}
	return nil
}

// HTTPAPNSClient implements APNSClient using HTTP/2
type HTTPAPNSClient struct {
	client    *http.Client
	authToken string
	teamID    string
	bundleID  string
	host      string
}

// NewHTTPAPNSClient creates a new APNS client
func NewHTTPAPNSClient(authToken, teamID, bundleID string, production bool) *HTTPAPNSClient {
	host := "https://api.sandbox.push.apple.com"
	if production {
		host = "https://api.push.apple.com"
	}
	return &HTTPAPNSClient{
		client:    &http.Client{Timeout: 30 * time.Second},
		authToken: authToken,
		teamID:    teamID,
		bundleID:  bundleID,
		host:      host,
	}
}

func (c *HTTPAPNSClient) Send(ctx context.Context, token string, payload *APNSPayload) error {
	url := fmt.Sprintf("%s/3/device/%s", c.host, token)

	// Build the aps payload
	apsPayload := map[string]interface{}{
		"aps": map[string]interface{}{
			"alert":            payload.Alert,
			"badge":            payload.Badge,
			"sound":            payload.Sound,
			"category":         payload.Category,
			"thread-id":        payload.ThreadID,
		},
	}

	// Add custom data
	for k, v := range payload.Data {
		apsPayload[k] = v
	}

	body, err := json.Marshal(apsPayload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+c.authToken)
	req.Header.Set("apns-topic", c.bundleID)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("APNS error: %d", resp.StatusCode)
	}

	return nil
}

// HTTPFCMClient implements FCMClient using HTTP
type HTTPFCMClient struct {
	client *http.Client
	apiKey string
}

// NewHTTPFCMClient creates a new FCM client
func NewHTTPFCMClient(apiKey string) *HTTPFCMClient {
	return &HTTPFCMClient{
		client: &http.Client{Timeout: 30 * time.Second},
		apiKey: apiKey,
	}
}

func (c *HTTPFCMClient) Send(ctx context.Context, token string, message *FCMMessage) error {
	url := "https://fcm.googleapis.com/fcm/send"

	payload := map[string]interface{}{
		"to":           token,
		"notification": message.Notification,
		"data":         message.Data,
	}

	if message.Android != nil {
		payload["android"] = message.Android
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "key="+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FCM error: %d", resp.StatusCode)
	}

	return nil
}

// SQLiteRepository implements Repository
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new repository
func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	repo := &SQLiteRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS push_devices (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			device_id TEXT,
			device_name TEXT,
			device_model TEXT,
			os_version TEXT,
			app_version TEXT,
			endpoint TEXT,
			p256dh TEXT,
			auth TEXT,
			enabled INTEGER DEFAULT 1,
			badge_count INTEGER DEFAULT 0,
			preferences TEXT,
			last_active DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS push_notifications (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			type TEXT NOT NULL,
			priority TEXT DEFAULT 'normal',
			title TEXT NOT NULL,
			body TEXT,
			subtitle TEXT,
			image_url TEXT,
			actions TEXT,
			data TEXT,
			badge INTEGER,
			sound TEXT,
			category TEXT,
			thread_id TEXT,
			channel_id TEXT,
			tag TEXT,
			collapse_key TEXT,
			ttl INTEGER,
			status TEXT DEFAULT 'pending',
			sent_at DATETIME,
			delivered_at DATETIME,
			failed_at DATETIME,
			error TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_device_account ON push_devices(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_device_token ON push_devices(token)`,
		`CREATE INDEX IF NOT EXISTS idx_notification_status ON push_notifications(status)`,
		`CREATE INDEX IF NOT EXISTS idx_notification_device ON push_notifications(device_id)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) SaveDevice(ctx context.Context, device *Device) error {
	prefsJSON, _ := json.Marshal(device.Preferences)

	query := `
	INSERT INTO push_devices (
		id, account_id, org_id, provider, token, device_id, device_name,
		device_model, os_version, app_version, endpoint, p256dh, auth,
		enabled, badge_count, preferences, last_active, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(token) DO UPDATE SET
		account_id = excluded.account_id,
		device_name = excluded.device_name,
		device_model = excluded.device_model,
		os_version = excluded.os_version,
		app_version = excluded.app_version,
		enabled = excluded.enabled,
		last_active = excluded.last_active,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		device.ID.String(), device.AccountID.String(), device.OrgID.String(),
		device.Provider, device.Token, device.DeviceID, device.DeviceName,
		device.DeviceModel, device.OSVersion, device.AppVersion, device.Endpoint,
		device.P256dh, device.Auth, device.Enabled, device.BadgeCount,
		string(prefsJSON), device.LastActive, device.CreatedAt, device.UpdatedAt)

	return err
}

func (r *SQLiteRepository) GetDevice(ctx context.Context, id uuid.UUID) (*Device, error) {
	query := `
	SELECT id, account_id, org_id, provider, token, device_id, device_name,
		device_model, os_version, app_version, endpoint, p256dh, auth,
		enabled, badge_count, preferences, last_active, created_at, updated_at
	FROM push_devices WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanDevice(row)
}

func (r *SQLiteRepository) GetDeviceByToken(ctx context.Context, token string) (*Device, error) {
	query := `
	SELECT id, account_id, org_id, provider, token, device_id, device_name,
		device_model, os_version, app_version, endpoint, p256dh, auth,
		enabled, badge_count, preferences, last_active, created_at, updated_at
	FROM push_devices WHERE token = ?
	`
	row := r.db.QueryRowContext(ctx, query, token)
	return r.scanDevice(row)
}

func (r *SQLiteRepository) GetDevicesForAccount(ctx context.Context, accountID uuid.UUID) ([]*Device, error) {
	query := `
	SELECT id, account_id, org_id, provider, token, device_id, device_name,
		device_model, os_version, app_version, endpoint, p256dh, auth,
		enabled, badge_count, preferences, last_active, created_at, updated_at
	FROM push_devices WHERE account_id = ?
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

func (r *SQLiteRepository) GetActiveDevices(ctx context.Context, accountID uuid.UUID) ([]*Device, error) {
	query := `
	SELECT id, account_id, org_id, provider, token, device_id, device_name,
		device_model, os_version, app_version, endpoint, p256dh, auth,
		enabled, badge_count, preferences, last_active, created_at, updated_at
	FROM push_devices WHERE account_id = ? AND enabled = 1
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanDevices(rows)
}

func (r *SQLiteRepository) UpdateDevice(ctx context.Context, device *Device) error {
	return r.SaveDevice(ctx, device)
}

func (r *SQLiteRepository) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM push_devices WHERE id = ?", id.String())
	return err
}

func (r *SQLiteRepository) scanDevice(row *sql.Row) (*Device, error) {
	var d Device
	var idStr, accountIDStr, orgIDStr string
	var prefsJSON string

	err := row.Scan(&idStr, &accountIDStr, &orgIDStr, &d.Provider, &d.Token,
		&d.DeviceID, &d.DeviceName, &d.DeviceModel, &d.OSVersion, &d.AppVersion,
		&d.Endpoint, &d.P256dh, &d.Auth, &d.Enabled, &d.BadgeCount,
		&prefsJSON, &d.LastActive, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}

	d.ID, _ = uuid.Parse(idStr)
	d.AccountID, _ = uuid.Parse(accountIDStr)
	d.OrgID, _ = uuid.Parse(orgIDStr)
	if prefsJSON != "" {
		var prefs DevicePreferences
		_ = json.Unmarshal([]byte(prefsJSON), &prefs)
		d.Preferences = &prefs
	}

	return &d, nil
}

func (r *SQLiteRepository) scanDevices(rows *sql.Rows) ([]*Device, error) {
	var devices []*Device
	for rows.Next() {
		var d Device
		var idStr, accountIDStr, orgIDStr string
		var prefsJSON string

		err := rows.Scan(&idStr, &accountIDStr, &orgIDStr, &d.Provider, &d.Token,
			&d.DeviceID, &d.DeviceName, &d.DeviceModel, &d.OSVersion, &d.AppVersion,
			&d.Endpoint, &d.P256dh, &d.Auth, &d.Enabled, &d.BadgeCount,
			&prefsJSON, &d.LastActive, &d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			return nil, err
		}

		d.ID, _ = uuid.Parse(idStr)
		d.AccountID, _ = uuid.Parse(accountIDStr)
		d.OrgID, _ = uuid.Parse(orgIDStr)
		if prefsJSON != "" {
			var prefs DevicePreferences
			_ = json.Unmarshal([]byte(prefsJSON), &prefs)
			d.Preferences = &prefs
		}

		devices = append(devices, &d)
	}
	return devices, rows.Err()
}

// Notification repository methods
func (r *SQLiteRepository) SaveNotification(ctx context.Context, n *Notification) error {
	actionsJSON, _ := json.Marshal(n.Actions)
	dataJSON, _ := json.Marshal(n.Data)

	query := `
	INSERT INTO push_notifications (
		id, account_id, device_id, type, priority, title, body, subtitle,
		image_url, actions, data, badge, sound, category, thread_id,
		channel_id, tag, collapse_key, ttl, status, sent_at, delivered_at,
		failed_at, error, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		n.ID.String(), n.AccountID.String(), n.DeviceID.String(), n.Type,
		n.Priority, n.Title, n.Body, n.Subtitle, n.ImageURL, string(actionsJSON),
		string(dataJSON), n.Badge, n.Sound, n.Category, n.ThreadID, n.ChannelID,
		n.Tag, n.CollapseKey, n.TTL, n.Status, n.SentAt, n.DeliveredAt,
		n.FailedAt, n.Error, n.CreatedAt)

	return err
}

func (r *SQLiteRepository) GetNotification(ctx context.Context, id uuid.UUID) (*Notification, error) {
	query := `
	SELECT id, account_id, device_id, type, priority, title, body, subtitle,
		image_url, actions, data, badge, sound, category, thread_id,
		channel_id, tag, collapse_key, ttl, status, sent_at, delivered_at,
		failed_at, error, created_at
	FROM push_notifications WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var n Notification
	var idStr, accountIDStr, deviceIDStr string
	var actionsJSON, dataJSON string

	err := row.Scan(&idStr, &accountIDStr, &deviceIDStr, &n.Type, &n.Priority,
		&n.Title, &n.Body, &n.Subtitle, &n.ImageURL, &actionsJSON, &dataJSON,
		&n.Badge, &n.Sound, &n.Category, &n.ThreadID, &n.ChannelID, &n.Tag,
		&n.CollapseKey, &n.TTL, &n.Status, &n.SentAt, &n.DeliveredAt,
		&n.FailedAt, &n.Error, &n.CreatedAt)
	if err != nil {
		return nil, err
	}

	n.ID, _ = uuid.Parse(idStr)
	n.AccountID, _ = uuid.Parse(accountIDStr)
	n.DeviceID, _ = uuid.Parse(deviceIDStr)
	_ = json.Unmarshal([]byte(actionsJSON), &n.Actions)
	_ = json.Unmarshal([]byte(dataJSON), &n.Data)

	return &n, nil
}

func (r *SQLiteRepository) GetPendingNotifications(ctx context.Context, limit int) ([]*Notification, error) {
	query := `
	SELECT id, account_id, device_id, type, priority, title, body, subtitle,
		image_url, actions, data, badge, sound, category, thread_id,
		channel_id, tag, collapse_key, ttl, status, sent_at, delivered_at,
		failed_at, error, created_at
	FROM push_notifications WHERE status = 'pending' LIMIT ?
	`
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []*Notification
	for rows.Next() {
		var n Notification
		var idStr, accountIDStr, deviceIDStr string
		var actionsJSON, dataJSON string

		err := rows.Scan(&idStr, &accountIDStr, &deviceIDStr, &n.Type, &n.Priority,
			&n.Title, &n.Body, &n.Subtitle, &n.ImageURL, &actionsJSON, &dataJSON,
			&n.Badge, &n.Sound, &n.Category, &n.ThreadID, &n.ChannelID, &n.Tag,
			&n.CollapseKey, &n.TTL, &n.Status, &n.SentAt, &n.DeliveredAt,
			&n.FailedAt, &n.Error, &n.CreatedAt)
		if err != nil {
			return nil, err
		}

		n.ID, _ = uuid.Parse(idStr)
		n.AccountID, _ = uuid.Parse(accountIDStr)
		n.DeviceID, _ = uuid.Parse(deviceIDStr)
		_ = json.Unmarshal([]byte(actionsJSON), &n.Actions)
		_ = json.Unmarshal([]byte(dataJSON), &n.Data)

		notifications = append(notifications, &n)
	}
	return notifications, rows.Err()
}

func (r *SQLiteRepository) UpdateNotificationStatus(ctx context.Context, id uuid.UUID, status string, errMsg string) error {
	now := time.Now()
	var query string
	var args []interface{}

	switch status {
	case "sent":
		query = "UPDATE push_notifications SET status = ?, sent_at = ? WHERE id = ?"
		args = []interface{}{status, now, id.String()}
	case "delivered":
		query = "UPDATE push_notifications SET status = ?, delivered_at = ? WHERE id = ?"
		args = []interface{}{status, now, id.String()}
	case "failed":
		query = "UPDATE push_notifications SET status = ?, failed_at = ?, error = ? WHERE id = ?"
		args = []interface{}{status, now, errMsg, id.String()}
	default:
		query = "UPDATE push_notifications SET status = ? WHERE id = ?"
		args = []interface{}{status, id.String()}
	}

	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}

func (r *SQLiteRepository) GetNotificationHistory(ctx context.Context, accountID uuid.UUID, limit int) ([]*Notification, error) {
	query := `
	SELECT id, account_id, device_id, type, priority, title, body, subtitle,
		image_url, actions, data, badge, sound, category, thread_id,
		channel_id, tag, collapse_key, ttl, status, sent_at, delivered_at,
		failed_at, error, created_at
	FROM push_notifications WHERE account_id = ?
	ORDER BY created_at DESC LIMIT ?
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []*Notification
	for rows.Next() {
		var n Notification
		var idStr, accountIDStr, deviceIDStr string
		var actionsJSON, dataJSON string

		err := rows.Scan(&idStr, &accountIDStr, &deviceIDStr, &n.Type, &n.Priority,
			&n.Title, &n.Body, &n.Subtitle, &n.ImageURL, &actionsJSON, &dataJSON,
			&n.Badge, &n.Sound, &n.Category, &n.ThreadID, &n.ChannelID, &n.Tag,
			&n.CollapseKey, &n.TTL, &n.Status, &n.SentAt, &n.DeliveredAt,
			&n.FailedAt, &n.Error, &n.CreatedAt)
		if err != nil {
			return nil, err
		}

		n.ID, _ = uuid.Parse(idStr)
		n.AccountID, _ = uuid.Parse(accountIDStr)
		n.DeviceID, _ = uuid.Parse(deviceIDStr)
		_ = json.Unmarshal([]byte(actionsJSON), &n.Actions)
		_ = json.Unmarshal([]byte(dataJSON), &n.Data)

		notifications = append(notifications, &n)
	}
	return notifications, rows.Err()
}
