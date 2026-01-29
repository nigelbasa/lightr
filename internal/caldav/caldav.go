package caldav

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Calendar represents a calendar
type Calendar struct {
	ID          uuid.UUID `json:"id"`
	AccountID   uuid.UUID `json:"account_id"`
	OrgID       uuid.UUID `json:"org_id"`
	
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Color       string    `json:"color,omitempty"`      // Hex color
	Timezone    string    `json:"timezone,omitempty"`
	
	// CalDAV properties
	CalendarURL string    `json:"calendar_url"`
	CTag        string    `json:"ctag"`                 // Calendar tag for sync
	SyncToken   string    `json:"sync_token,omitempty"`
	
	// Settings
	IsDefault   bool      `json:"is_default"`
	IsReadOnly  bool      `json:"is_read_only"`
	IsShared    bool      `json:"is_shared"`
	
	// Supported components
	SupportsEvents bool   `json:"supports_events"`
	SupportsTodos  bool   `json:"supports_todos"`
	
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Event represents a calendar event
type Event struct {
	ID          uuid.UUID `json:"id"`
	CalendarID  uuid.UUID `json:"calendar_id"`
	AccountID   uuid.UUID `json:"account_id"`
	
	// iCalendar UID
	UID         string    `json:"uid"`
	ETag        string    `json:"etag"`
	
	// Event details
	Summary     string    `json:"summary"`
	Description string    `json:"description,omitempty"`
	Location    string    `json:"location,omitempty"`
	URL         string    `json:"url,omitempty"`
	
	// Time
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	AllDay      bool      `json:"all_day"`
	Timezone    string    `json:"timezone,omitempty"`
	
	// Recurrence
	IsRecurring bool      `json:"is_recurring"`
	RRule       string    `json:"rrule,omitempty"`      // RRULE string
	RecurID     string    `json:"recur_id,omitempty"`   // Recurrence instance ID
	Exceptions  []string  `json:"exceptions,omitempty"` // EXDATE values
	
	// Status
	Status      string    `json:"status"`      // CONFIRMED, TENTATIVE, CANCELLED
	Transp      string    `json:"transp"`      // OPAQUE, TRANSPARENT (busy/free)
	
	// Organizer & Attendees
	Organizer   *Attendee   `json:"organizer,omitempty"`
	Attendees   []Attendee  `json:"attendees,omitempty"`
	
	// Alarms
	Alarms      []Alarm     `json:"alarms,omitempty"`
	
	// Categories/Tags
	Categories  []string    `json:"categories,omitempty"`
	
	// Priority (1=highest, 9=lowest, 0=undefined)
	Priority    int         `json:"priority,omitempty"`
	
	// Sequence number for updates
	Sequence    int         `json:"sequence"`
	
	// Raw iCalendar data
	ICalData    string      `json:"-"`
	
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// Attendee represents an event attendee
type Attendee struct {
	Email       string `json:"email"`
	Name        string `json:"name,omitempty"`
	Role        string `json:"role,omitempty"`       // REQ-PARTICIPANT, OPT-PARTICIPANT, CHAIR
	PartStat    string `json:"part_stat,omitempty"`  // NEEDS-ACTION, ACCEPTED, DECLINED, TENTATIVE
	RSVP        bool   `json:"rsvp,omitempty"`
}

// Alarm represents an event alarm/reminder
type Alarm struct {
	Action      string        `json:"action"`      // DISPLAY, EMAIL, AUDIO
	Trigger     string        `json:"trigger"`     // e.g., "-PT15M" (15 min before)
	Description string        `json:"description,omitempty"`
}

// Todo represents a task/todo item
type Todo struct {
	ID          uuid.UUID `json:"id"`
	CalendarID  uuid.UUID `json:"calendar_id"`
	AccountID   uuid.UUID `json:"account_id"`
	
	UID         string    `json:"uid"`
	ETag        string    `json:"etag"`
	
	Summary     string    `json:"summary"`
	Description string    `json:"description,omitempty"`
	Location    string    `json:"location,omitempty"`
	
	// Dates
	DueDate     *time.Time `json:"due_date,omitempty"`
	StartDate   *time.Time `json:"start_date,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	
	// Status
	Status      string    `json:"status"` // NEEDS-ACTION, IN-PROCESS, COMPLETED, CANCELLED
	PercentComplete int   `json:"percent_complete"`
	Priority    int       `json:"priority"`
	
	// Recurrence
	IsRecurring bool      `json:"is_recurring"`
	RRule       string    `json:"rrule,omitempty"`
	
	Categories  []string  `json:"categories,omitempty"`
	Alarms      []Alarm   `json:"alarms,omitempty"`
	
	ICalData    string    `json:"-"`
	
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FreeBusy represents free/busy information
type FreeBusy struct {
	Email       string          `json:"email"`
	Start       time.Time       `json:"start"`
	End         time.Time       `json:"end"`
	Periods     []FreeBusyPeriod `json:"periods"`
}

// FreeBusyPeriod represents a single busy period
type FreeBusyPeriod struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Type     string    `json:"type"` // BUSY, BUSY-UNAVAILABLE, BUSY-TENTATIVE
}

// CalDAVService handles calendar operations
type CalDAVService struct {
	mu     sync.RWMutex
	repo   CalendarRepository
	logger Logger
}

// CalendarRepository interface
type CalendarRepository interface {
	// Calendars
	SaveCalendar(ctx context.Context, cal *Calendar) error
	GetCalendar(ctx context.Context, id uuid.UUID) (*Calendar, error)
	GetCalendarsForAccount(ctx context.Context, accountID uuid.UUID) ([]*Calendar, error)
	DeleteCalendar(ctx context.Context, id uuid.UUID) error
	UpdateCTag(ctx context.Context, calendarID uuid.UUID) error
	
	// Events
	SaveEvent(ctx context.Context, event *Event) error
	GetEvent(ctx context.Context, id uuid.UUID) (*Event, error)
	GetEventByUID(ctx context.Context, calendarID uuid.UUID, uid string) (*Event, error)
	GetEventsInRange(ctx context.Context, calendarID uuid.UUID, start, end time.Time) ([]*Event, error)
	GetEventsSince(ctx context.Context, calendarID uuid.UUID, since time.Time) ([]*Event, error)
	DeleteEvent(ctx context.Context, id uuid.UUID) error
	
	// Todos
	SaveTodo(ctx context.Context, todo *Todo) error
	GetTodo(ctx context.Context, id uuid.UUID) (*Todo, error)
	GetTodosForCalendar(ctx context.Context, calendarID uuid.UUID) ([]*Todo, error)
	DeleteTodo(ctx context.Context, id uuid.UUID) error
}

// Logger interface
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewCalDAVService creates a new CalDAV service
func NewCalDAVService(repo CalendarRepository, logger Logger) *CalDAVService {
	return &CalDAVService{
		repo:   repo,
		logger: logger,
	}
}

// Calendar Management

// CreateCalendar creates a new calendar
func (s *CalDAVService) CreateCalendar(ctx context.Context, cal *Calendar) error {
	cal.ID = uuid.New()
	cal.CTag = generateCTag()
	cal.CalendarURL = fmt.Sprintf("/calendars/%s/%s/", cal.AccountID.String(), cal.ID.String())
	cal.SupportsEvents = true
	cal.SupportsTodos = true
	cal.CreatedAt = time.Now()
	cal.UpdatedAt = time.Now()

	if err := s.repo.SaveCalendar(ctx, cal); err != nil {
		return err
	}

	s.logger.Info("created calendar", "id", cal.ID, "name", cal.Name)
	return nil
}

// GetCalendar retrieves a calendar by ID
func (s *CalDAVService) GetCalendar(ctx context.Context, id uuid.UUID) (*Calendar, error) {
	return s.repo.GetCalendar(ctx, id)
}

// GetCalendars retrieves all calendars for an account
func (s *CalDAVService) GetCalendars(ctx context.Context, accountID uuid.UUID) ([]*Calendar, error) {
	return s.repo.GetCalendarsForAccount(ctx, accountID)
}

// DeleteCalendar deletes a calendar
func (s *CalDAVService) DeleteCalendar(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteCalendar(ctx, id)
}

// Event Management

// CreateEvent creates a new event
func (s *CalDAVService) CreateEvent(ctx context.Context, event *Event) error {
	event.ID = uuid.New()
	if event.UID == "" {
		event.UID = uuid.New().String()
	}
	event.ETag = generateETag()
	event.Sequence = 0
	event.CreatedAt = time.Now()
	event.UpdatedAt = time.Now()

	// Generate iCal data
	event.ICalData = s.eventToICal(event)

	if err := s.repo.SaveEvent(ctx, event); err != nil {
		return err
	}

	// Update calendar CTag
	s.repo.UpdateCTag(ctx, event.CalendarID)

	s.logger.Info("created event", "id", event.ID, "summary", event.Summary)
	return nil
}

// UpdateEvent updates an existing event
func (s *CalDAVService) UpdateEvent(ctx context.Context, event *Event) error {
	event.Sequence++
	event.ETag = generateETag()
	event.UpdatedAt = time.Now()
	event.ICalData = s.eventToICal(event)

	if err := s.repo.SaveEvent(ctx, event); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, event.CalendarID)
	s.logger.Info("updated event", "id", event.ID)
	return nil
}

// GetEvent retrieves an event by ID
func (s *CalDAVService) GetEvent(ctx context.Context, id uuid.UUID) (*Event, error) {
	return s.repo.GetEvent(ctx, id)
}

// GetEventByUID retrieves an event by its iCalendar UID
func (s *CalDAVService) GetEventByUID(ctx context.Context, calendarID uuid.UUID, uid string) (*Event, error) {
	return s.repo.GetEventByUID(ctx, calendarID, uid)
}

// GetEventsInRange retrieves events in a time range
func (s *CalDAVService) GetEventsInRange(ctx context.Context, calendarID uuid.UUID, start, end time.Time) ([]*Event, error) {
	return s.repo.GetEventsInRange(ctx, calendarID, start, end)
}

// DeleteEvent deletes an event
func (s *CalDAVService) DeleteEvent(ctx context.Context, id uuid.UUID) error {
	event, err := s.repo.GetEvent(ctx, id)
	if err != nil {
		return err
	}

	if err := s.repo.DeleteEvent(ctx, id); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, event.CalendarID)
	return nil
}

// Todo Management

// CreateTodo creates a new todo
func (s *CalDAVService) CreateTodo(ctx context.Context, todo *Todo) error {
	todo.ID = uuid.New()
	if todo.UID == "" {
		todo.UID = uuid.New().String()
	}
	todo.ETag = generateETag()
	todo.Status = "NEEDS-ACTION"
	todo.CreatedAt = time.Now()
	todo.UpdatedAt = time.Now()

	todo.ICalData = s.todoToICal(todo)

	if err := s.repo.SaveTodo(ctx, todo); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, todo.CalendarID)
	return nil
}

// UpdateTodo updates a todo
func (s *CalDAVService) UpdateTodo(ctx context.Context, todo *Todo) error {
	todo.ETag = generateETag()
	todo.UpdatedAt = time.Now()
	todo.ICalData = s.todoToICal(todo)

	if err := s.repo.SaveTodo(ctx, todo); err != nil {
		return err
	}

	s.repo.UpdateCTag(ctx, todo.CalendarID)
	return nil
}

// CompleteTodo marks a todo as complete
func (s *CalDAVService) CompleteTodo(ctx context.Context, id uuid.UUID) error {
	todo, err := s.repo.GetTodo(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	todo.Status = "COMPLETED"
	todo.PercentComplete = 100
	todo.CompletedAt = &now

	return s.UpdateTodo(ctx, todo)
}

// GetTodos retrieves todos for a calendar
func (s *CalDAVService) GetTodos(ctx context.Context, calendarID uuid.UUID) ([]*Todo, error) {
	return s.repo.GetTodosForCalendar(ctx, calendarID)
}

// Free/Busy

// GetFreeBusy retrieves free/busy information for a user
func (s *CalDAVService) GetFreeBusy(ctx context.Context, accountID uuid.UUID, start, end time.Time) (*FreeBusy, error) {
	calendars, err := s.repo.GetCalendarsForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	var periods []FreeBusyPeriod
	for _, cal := range calendars {
		events, err := s.repo.GetEventsInRange(ctx, cal.ID, start, end)
		if err != nil {
			continue
		}

		for _, event := range events {
			if event.Transp == "TRANSPARENT" {
				continue // Free time
			}

			busyType := "BUSY"
			if event.Status == "TENTATIVE" {
				busyType = "BUSY-TENTATIVE"
			}

			periods = append(periods, FreeBusyPeriod{
				Start: event.StartTime,
				End:   event.EndTime,
				Type:  busyType,
			})
		}
	}

	return &FreeBusy{
		Start:   start,
		End:     end,
		Periods: periods,
	}, nil
}

// iCalendar Generation

func (s *CalDAVService) eventToICal(event *Event) string {
	var sb strings.Builder

	sb.WriteString("BEGIN:VCALENDAR\r\n")
	sb.WriteString("VERSION:2.0\r\n")
	sb.WriteString("PRODID:-//Lightr//Calendar//EN\r\n")
	sb.WriteString("BEGIN:VEVENT\r\n")

	sb.WriteString(fmt.Sprintf("UID:%s\r\n", event.UID))
	sb.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", formatICalTime(time.Now())))
	sb.WriteString(fmt.Sprintf("CREATED:%s\r\n", formatICalTime(event.CreatedAt)))
	sb.WriteString(fmt.Sprintf("LAST-MODIFIED:%s\r\n", formatICalTime(event.UpdatedAt)))
	sb.WriteString(fmt.Sprintf("SEQUENCE:%d\r\n", event.Sequence))

	if event.AllDay {
		sb.WriteString(fmt.Sprintf("DTSTART;VALUE=DATE:%s\r\n", event.StartTime.Format("20060102")))
		sb.WriteString(fmt.Sprintf("DTEND;VALUE=DATE:%s\r\n", event.EndTime.Format("20060102")))
	} else {
		sb.WriteString(fmt.Sprintf("DTSTART:%s\r\n", formatICalTime(event.StartTime)))
		sb.WriteString(fmt.Sprintf("DTEND:%s\r\n", formatICalTime(event.EndTime)))
	}

	sb.WriteString(fmt.Sprintf("SUMMARY:%s\r\n", escapeICal(event.Summary)))
	if event.Description != "" {
		sb.WriteString(fmt.Sprintf("DESCRIPTION:%s\r\n", escapeICal(event.Description)))
	}
	if event.Location != "" {
		sb.WriteString(fmt.Sprintf("LOCATION:%s\r\n", escapeICal(event.Location)))
	}

	sb.WriteString(fmt.Sprintf("STATUS:%s\r\n", event.Status))
	sb.WriteString(fmt.Sprintf("TRANSP:%s\r\n", event.Transp))

	if event.IsRecurring && event.RRule != "" {
		sb.WriteString(fmt.Sprintf("RRULE:%s\r\n", event.RRule))
	}

	if event.Organizer != nil {
		sb.WriteString(fmt.Sprintf("ORGANIZER;CN=%s:mailto:%s\r\n", 
			escapeICal(event.Organizer.Name), event.Organizer.Email))
	}

	for _, attendee := range event.Attendees {
		sb.WriteString(fmt.Sprintf("ATTENDEE;CN=%s;PARTSTAT=%s;ROLE=%s:mailto:%s\r\n",
			escapeICal(attendee.Name), attendee.PartStat, attendee.Role, attendee.Email))
	}

	for _, alarm := range event.Alarms {
		sb.WriteString("BEGIN:VALARM\r\n")
		sb.WriteString(fmt.Sprintf("ACTION:%s\r\n", alarm.Action))
		sb.WriteString(fmt.Sprintf("TRIGGER:%s\r\n", alarm.Trigger))
		if alarm.Description != "" {
			sb.WriteString(fmt.Sprintf("DESCRIPTION:%s\r\n", escapeICal(alarm.Description)))
		}
		sb.WriteString("END:VALARM\r\n")
	}

	sb.WriteString("END:VEVENT\r\n")
	sb.WriteString("END:VCALENDAR\r\n")

	return sb.String()
}

func (s *CalDAVService) todoToICal(todo *Todo) string {
	var sb strings.Builder

	sb.WriteString("BEGIN:VCALENDAR\r\n")
	sb.WriteString("VERSION:2.0\r\n")
	sb.WriteString("PRODID:-//Lightr//Calendar//EN\r\n")
	sb.WriteString("BEGIN:VTODO\r\n")

	sb.WriteString(fmt.Sprintf("UID:%s\r\n", todo.UID))
	sb.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", formatICalTime(time.Now())))
	sb.WriteString(fmt.Sprintf("CREATED:%s\r\n", formatICalTime(todo.CreatedAt)))
	sb.WriteString(fmt.Sprintf("LAST-MODIFIED:%s\r\n", formatICalTime(todo.UpdatedAt)))

	sb.WriteString(fmt.Sprintf("SUMMARY:%s\r\n", escapeICal(todo.Summary)))
	if todo.Description != "" {
		sb.WriteString(fmt.Sprintf("DESCRIPTION:%s\r\n", escapeICal(todo.Description)))
	}

	if todo.DueDate != nil {
		sb.WriteString(fmt.Sprintf("DUE:%s\r\n", formatICalTime(*todo.DueDate)))
	}

	sb.WriteString(fmt.Sprintf("STATUS:%s\r\n", todo.Status))
	sb.WriteString(fmt.Sprintf("PERCENT-COMPLETE:%d\r\n", todo.PercentComplete))

	if todo.CompletedAt != nil {
		sb.WriteString(fmt.Sprintf("COMPLETED:%s\r\n", formatICalTime(*todo.CompletedAt)))
	}

	if todo.Priority > 0 {
		sb.WriteString(fmt.Sprintf("PRIORITY:%d\r\n", todo.Priority))
	}

	sb.WriteString("END:VTODO\r\n")
	sb.WriteString("END:VCALENDAR\r\n")

	return sb.String()
}

// Helpers

func generateCTag() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func generateETag() string {
	return fmt.Sprintf("\"%s\"", uuid.New().String()[:8])
}

func formatICalTime(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

func escapeICal(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// SQLite Repository

// SQLiteCalendarRepository implements CalendarRepository
type SQLiteCalendarRepository struct {
	db *sql.DB
}

// NewSQLiteCalendarRepository creates a new repository
func NewSQLiteCalendarRepository(db *sql.DB) (*SQLiteCalendarRepository, error) {
	repo := &SQLiteCalendarRepository{db: db}
	if err := repo.migrate(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteCalendarRepository) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS calendars (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			color TEXT,
			timezone TEXT,
			calendar_url TEXT NOT NULL,
			ctag TEXT NOT NULL,
			sync_token TEXT,
			is_default INTEGER DEFAULT 0,
			is_read_only INTEGER DEFAULT 0,
			is_shared INTEGER DEFAULT 0,
			supports_events INTEGER DEFAULT 1,
			supports_todos INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		
		`CREATE TABLE IF NOT EXISTS calendar_events (
			id TEXT PRIMARY KEY,
			calendar_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			uid TEXT NOT NULL,
			etag TEXT NOT NULL,
			summary TEXT NOT NULL,
			description TEXT,
			location TEXT,
			url TEXT,
			start_time DATETIME NOT NULL,
			end_time DATETIME NOT NULL,
			all_day INTEGER DEFAULT 0,
			timezone TEXT,
			is_recurring INTEGER DEFAULT 0,
			rrule TEXT,
			recur_id TEXT,
			exceptions TEXT,
			status TEXT DEFAULT 'CONFIRMED',
			transp TEXT DEFAULT 'OPAQUE',
			organizer TEXT,
			attendees TEXT,
			alarms TEXT,
			categories TEXT,
			priority INTEGER DEFAULT 0,
			sequence INTEGER DEFAULT 0,
			ical_data TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(calendar_id, uid)
		)`,
		
		`CREATE TABLE IF NOT EXISTS calendar_todos (
			id TEXT PRIMARY KEY,
			calendar_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			uid TEXT NOT NULL,
			etag TEXT NOT NULL,
			summary TEXT NOT NULL,
			description TEXT,
			location TEXT,
			due_date DATETIME,
			start_date DATETIME,
			completed_at DATETIME,
			status TEXT DEFAULT 'NEEDS-ACTION',
			percent_complete INTEGER DEFAULT 0,
			priority INTEGER DEFAULT 0,
			is_recurring INTEGER DEFAULT 0,
			rrule TEXT,
			categories TEXT,
			alarms TEXT,
			ical_data TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(calendar_id, uid)
		)`,
		
		`CREATE INDEX IF NOT EXISTS idx_calendar_account ON calendars(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_event_calendar ON calendar_events(calendar_id)`,
		`CREATE INDEX IF NOT EXISTS idx_event_time ON calendar_events(start_time, end_time)`,
		`CREATE INDEX IF NOT EXISTS idx_todo_calendar ON calendar_todos(calendar_id)`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// Calendar methods

func (r *SQLiteCalendarRepository) SaveCalendar(ctx context.Context, cal *Calendar) error {
	query := `
	INSERT INTO calendars (
		id, account_id, org_id, name, description, color, timezone, calendar_url,
		ctag, sync_token, is_default, is_read_only, is_shared, supports_events,
		supports_todos, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		name = excluded.name,
		description = excluded.description,
		color = excluded.color,
		timezone = excluded.timezone,
		ctag = excluded.ctag,
		sync_token = excluded.sync_token,
		is_default = excluded.is_default,
		is_read_only = excluded.is_read_only,
		is_shared = excluded.is_shared,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		cal.ID.String(), cal.AccountID.String(), cal.OrgID.String(), cal.Name,
		cal.Description, cal.Color, cal.Timezone, cal.CalendarURL, cal.CTag,
		cal.SyncToken, cal.IsDefault, cal.IsReadOnly, cal.IsShared,
		cal.SupportsEvents, cal.SupportsTodos, cal.CreatedAt, cal.UpdatedAt)

	return err
}

func (r *SQLiteCalendarRepository) GetCalendar(ctx context.Context, id uuid.UUID) (*Calendar, error) {
	query := `
	SELECT id, account_id, org_id, name, description, color, timezone, calendar_url,
		ctag, sync_token, is_default, is_read_only, is_shared, supports_events,
		supports_todos, created_at, updated_at
	FROM calendars WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanCalendar(row)
}

func (r *SQLiteCalendarRepository) GetCalendarsForAccount(ctx context.Context, accountID uuid.UUID) ([]*Calendar, error) {
	query := `
	SELECT id, account_id, org_id, name, description, color, timezone, calendar_url,
		ctag, sync_token, is_default, is_read_only, is_shared, supports_events,
		supports_todos, created_at, updated_at
	FROM calendars WHERE account_id = ?
	`
	rows, err := r.db.QueryContext(ctx, query, accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var calendars []*Calendar
	for rows.Next() {
		var cal Calendar
		var idStr, accountIDStr, orgIDStr string

		err := rows.Scan(&idStr, &accountIDStr, &orgIDStr, &cal.Name, &cal.Description,
			&cal.Color, &cal.Timezone, &cal.CalendarURL, &cal.CTag, &cal.SyncToken,
			&cal.IsDefault, &cal.IsReadOnly, &cal.IsShared, &cal.SupportsEvents,
			&cal.SupportsTodos, &cal.CreatedAt, &cal.UpdatedAt)
		if err != nil {
			return nil, err
		}

		cal.ID, _ = uuid.Parse(idStr)
		cal.AccountID, _ = uuid.Parse(accountIDStr)
		cal.OrgID, _ = uuid.Parse(orgIDStr)

		calendars = append(calendars, &cal)
	}
	return calendars, rows.Err()
}

func (r *SQLiteCalendarRepository) DeleteCalendar(ctx context.Context, id uuid.UUID) error {
	// Delete events and todos first
	r.db.ExecContext(ctx, "DELETE FROM calendar_events WHERE calendar_id = ?", id.String())
	r.db.ExecContext(ctx, "DELETE FROM calendar_todos WHERE calendar_id = ?", id.String())
	_, err := r.db.ExecContext(ctx, "DELETE FROM calendars WHERE id = ?", id.String())
	return err
}

func (r *SQLiteCalendarRepository) UpdateCTag(ctx context.Context, calendarID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE calendars SET ctag = ?, updated_at = ? WHERE id = ?",
		generateCTag(), time.Now(), calendarID.String())
	return err
}

func (r *SQLiteCalendarRepository) scanCalendar(row *sql.Row) (*Calendar, error) {
	var cal Calendar
	var idStr, accountIDStr, orgIDStr string

	err := row.Scan(&idStr, &accountIDStr, &orgIDStr, &cal.Name, &cal.Description,
		&cal.Color, &cal.Timezone, &cal.CalendarURL, &cal.CTag, &cal.SyncToken,
		&cal.IsDefault, &cal.IsReadOnly, &cal.IsShared, &cal.SupportsEvents,
		&cal.SupportsTodos, &cal.CreatedAt, &cal.UpdatedAt)
	if err != nil {
		return nil, err
	}

	cal.ID, _ = uuid.Parse(idStr)
	cal.AccountID, _ = uuid.Parse(accountIDStr)
	cal.OrgID, _ = uuid.Parse(orgIDStr)

	return &cal, nil
}

// Event methods

func (r *SQLiteCalendarRepository) SaveEvent(ctx context.Context, event *Event) error {
	organizerJSON, _ := json.Marshal(event.Organizer)
	attendeesJSON, _ := json.Marshal(event.Attendees)
	alarmsJSON, _ := json.Marshal(event.Alarms)
	categoriesJSON, _ := json.Marshal(event.Categories)
	exceptionsJSON, _ := json.Marshal(event.Exceptions)

	query := `
	INSERT INTO calendar_events (
		id, calendar_id, account_id, uid, etag, summary, description, location, url,
		start_time, end_time, all_day, timezone, is_recurring, rrule, recur_id,
		exceptions, status, transp, organizer, attendees, alarms, categories,
		priority, sequence, ical_data, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(calendar_id, uid) DO UPDATE SET
		etag = excluded.etag,
		summary = excluded.summary,
		description = excluded.description,
		location = excluded.location,
		start_time = excluded.start_time,
		end_time = excluded.end_time,
		all_day = excluded.all_day,
		rrule = excluded.rrule,
		exceptions = excluded.exceptions,
		status = excluded.status,
		transp = excluded.transp,
		organizer = excluded.organizer,
		attendees = excluded.attendees,
		alarms = excluded.alarms,
		categories = excluded.categories,
		sequence = excluded.sequence,
		ical_data = excluded.ical_data,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		event.ID.String(), event.CalendarID.String(), event.AccountID.String(),
		event.UID, event.ETag, event.Summary, event.Description, event.Location,
		event.URL, event.StartTime, event.EndTime, event.AllDay, event.Timezone,
		event.IsRecurring, event.RRule, event.RecurID, string(exceptionsJSON),
		event.Status, event.Transp, string(organizerJSON), string(attendeesJSON),
		string(alarmsJSON), string(categoriesJSON), event.Priority, event.Sequence,
		event.ICalData, event.CreatedAt, event.UpdatedAt)

	return err
}

func (r *SQLiteCalendarRepository) GetEvent(ctx context.Context, id uuid.UUID) (*Event, error) {
	query := `
	SELECT id, calendar_id, account_id, uid, etag, summary, description, location, url,
		start_time, end_time, all_day, timezone, is_recurring, rrule, recur_id,
		exceptions, status, transp, organizer, attendees, alarms, categories,
		priority, sequence, ical_data, created_at, updated_at
	FROM calendar_events WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanEvent(row)
}

func (r *SQLiteCalendarRepository) GetEventByUID(ctx context.Context, calendarID uuid.UUID, uid string) (*Event, error) {
	query := `
	SELECT id, calendar_id, account_id, uid, etag, summary, description, location, url,
		start_time, end_time, all_day, timezone, is_recurring, rrule, recur_id,
		exceptions, status, transp, organizer, attendees, alarms, categories,
		priority, sequence, ical_data, created_at, updated_at
	FROM calendar_events WHERE calendar_id = ? AND uid = ?
	`
	row := r.db.QueryRowContext(ctx, query, calendarID.String(), uid)
	return r.scanEvent(row)
}

func (r *SQLiteCalendarRepository) GetEventsInRange(ctx context.Context, calendarID uuid.UUID, start, end time.Time) ([]*Event, error) {
	query := `
	SELECT id, calendar_id, account_id, uid, etag, summary, description, location, url,
		start_time, end_time, all_day, timezone, is_recurring, rrule, recur_id,
		exceptions, status, transp, organizer, attendees, alarms, categories,
		priority, sequence, ical_data, created_at, updated_at
	FROM calendar_events 
	WHERE calendar_id = ? AND start_time < ? AND end_time > ?
	ORDER BY start_time
	`
	rows, err := r.db.QueryContext(ctx, query, calendarID.String(), end, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanEvents(rows)
}

func (r *SQLiteCalendarRepository) GetEventsSince(ctx context.Context, calendarID uuid.UUID, since time.Time) ([]*Event, error) {
	query := `
	SELECT id, calendar_id, account_id, uid, etag, summary, description, location, url,
		start_time, end_time, all_day, timezone, is_recurring, rrule, recur_id,
		exceptions, status, transp, organizer, attendees, alarms, categories,
		priority, sequence, ical_data, created_at, updated_at
	FROM calendar_events 
	WHERE calendar_id = ? AND updated_at > ?
	`
	rows, err := r.db.QueryContext(ctx, query, calendarID.String(), since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanEvents(rows)
}

func (r *SQLiteCalendarRepository) DeleteEvent(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM calendar_events WHERE id = ?", id.String())
	return err
}

func (r *SQLiteCalendarRepository) scanEvent(row *sql.Row) (*Event, error) {
	var event Event
	var idStr, calIDStr, accountIDStr string
	var organizerJSON, attendeesJSON, alarmsJSON, categoriesJSON, exceptionsJSON string

	err := row.Scan(&idStr, &calIDStr, &accountIDStr, &event.UID, &event.ETag,
		&event.Summary, &event.Description, &event.Location, &event.URL,
		&event.StartTime, &event.EndTime, &event.AllDay, &event.Timezone,
		&event.IsRecurring, &event.RRule, &event.RecurID, &exceptionsJSON,
		&event.Status, &event.Transp, &organizerJSON, &attendeesJSON,
		&alarmsJSON, &categoriesJSON, &event.Priority, &event.Sequence,
		&event.ICalData, &event.CreatedAt, &event.UpdatedAt)
	if err != nil {
		return nil, err
	}

	event.ID, _ = uuid.Parse(idStr)
	event.CalendarID, _ = uuid.Parse(calIDStr)
	event.AccountID, _ = uuid.Parse(accountIDStr)
	
	if organizerJSON != "" {
		var org Attendee
		_ = json.Unmarshal([]byte(organizerJSON), &org)
		event.Organizer = &org
	}
	_ = json.Unmarshal([]byte(attendeesJSON), &event.Attendees)
	_ = json.Unmarshal([]byte(alarmsJSON), &event.Alarms)
	_ = json.Unmarshal([]byte(categoriesJSON), &event.Categories)
	_ = json.Unmarshal([]byte(exceptionsJSON), &event.Exceptions)

	return &event, nil
}

func (r *SQLiteCalendarRepository) scanEvents(rows *sql.Rows) ([]*Event, error) {
	var events []*Event
	for rows.Next() {
		var event Event
		var idStr, calIDStr, accountIDStr string
		var organizerJSON, attendeesJSON, alarmsJSON, categoriesJSON, exceptionsJSON string

		err := rows.Scan(&idStr, &calIDStr, &accountIDStr, &event.UID, &event.ETag,
			&event.Summary, &event.Description, &event.Location, &event.URL,
			&event.StartTime, &event.EndTime, &event.AllDay, &event.Timezone,
			&event.IsRecurring, &event.RRule, &event.RecurID, &exceptionsJSON,
			&event.Status, &event.Transp, &organizerJSON, &attendeesJSON,
			&alarmsJSON, &categoriesJSON, &event.Priority, &event.Sequence,
			&event.ICalData, &event.CreatedAt, &event.UpdatedAt)
		if err != nil {
			return nil, err
		}

		event.ID, _ = uuid.Parse(idStr)
		event.CalendarID, _ = uuid.Parse(calIDStr)
		event.AccountID, _ = uuid.Parse(accountIDStr)
		
		if organizerJSON != "" {
			var org Attendee
			_ = json.Unmarshal([]byte(organizerJSON), &org)
			event.Organizer = &org
		}
		_ = json.Unmarshal([]byte(attendeesJSON), &event.Attendees)
		_ = json.Unmarshal([]byte(alarmsJSON), &event.Alarms)
		_ = json.Unmarshal([]byte(categoriesJSON), &event.Categories)
		_ = json.Unmarshal([]byte(exceptionsJSON), &event.Exceptions)

		events = append(events, &event)
	}
	return events, rows.Err()
}

// Todo methods

func (r *SQLiteCalendarRepository) SaveTodo(ctx context.Context, todo *Todo) error {
	categoriesJSON, _ := json.Marshal(todo.Categories)
	alarmsJSON, _ := json.Marshal(todo.Alarms)

	query := `
	INSERT INTO calendar_todos (
		id, calendar_id, account_id, uid, etag, summary, description, location,
		due_date, start_date, completed_at, status, percent_complete, priority,
		is_recurring, rrule, categories, alarms, ical_data, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(calendar_id, uid) DO UPDATE SET
		etag = excluded.etag,
		summary = excluded.summary,
		description = excluded.description,
		due_date = excluded.due_date,
		completed_at = excluded.completed_at,
		status = excluded.status,
		percent_complete = excluded.percent_complete,
		priority = excluded.priority,
		categories = excluded.categories,
		alarms = excluded.alarms,
		ical_data = excluded.ical_data,
		updated_at = excluded.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		todo.ID.String(), todo.CalendarID.String(), todo.AccountID.String(),
		todo.UID, todo.ETag, todo.Summary, todo.Description, todo.Location,
		todo.DueDate, todo.StartDate, todo.CompletedAt, todo.Status,
		todo.PercentComplete, todo.Priority, todo.IsRecurring, todo.RRule,
		string(categoriesJSON), string(alarmsJSON), todo.ICalData,
		todo.CreatedAt, todo.UpdatedAt)

	return err
}

func (r *SQLiteCalendarRepository) GetTodo(ctx context.Context, id uuid.UUID) (*Todo, error) {
	query := `
	SELECT id, calendar_id, account_id, uid, etag, summary, description, location,
		due_date, start_date, completed_at, status, percent_complete, priority,
		is_recurring, rrule, categories, alarms, ical_data, created_at, updated_at
	FROM calendar_todos WHERE id = ?
	`
	row := r.db.QueryRowContext(ctx, query, id.String())

	var todo Todo
	var idStr, calIDStr, accountIDStr string
	var categoriesJSON, alarmsJSON string

	err := row.Scan(&idStr, &calIDStr, &accountIDStr, &todo.UID, &todo.ETag,
		&todo.Summary, &todo.Description, &todo.Location, &todo.DueDate,
		&todo.StartDate, &todo.CompletedAt, &todo.Status, &todo.PercentComplete,
		&todo.Priority, &todo.IsRecurring, &todo.RRule, &categoriesJSON,
		&alarmsJSON, &todo.ICalData, &todo.CreatedAt, &todo.UpdatedAt)
	if err != nil {
		return nil, err
	}

	todo.ID, _ = uuid.Parse(idStr)
	todo.CalendarID, _ = uuid.Parse(calIDStr)
	todo.AccountID, _ = uuid.Parse(accountIDStr)
	_ = json.Unmarshal([]byte(categoriesJSON), &todo.Categories)
	_ = json.Unmarshal([]byte(alarmsJSON), &todo.Alarms)

	return &todo, nil
}

func (r *SQLiteCalendarRepository) GetTodosForCalendar(ctx context.Context, calendarID uuid.UUID) ([]*Todo, error) {
	query := `
	SELECT id, calendar_id, account_id, uid, etag, summary, description, location,
		due_date, start_date, completed_at, status, percent_complete, priority,
		is_recurring, rrule, categories, alarms, ical_data, created_at, updated_at
	FROM calendar_todos WHERE calendar_id = ?
	`
	rows, err := r.db.QueryContext(ctx, query, calendarID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var todos []*Todo
	for rows.Next() {
		var todo Todo
		var idStr, calIDStr, accountIDStr string
		var categoriesJSON, alarmsJSON string

		err := rows.Scan(&idStr, &calIDStr, &accountIDStr, &todo.UID, &todo.ETag,
			&todo.Summary, &todo.Description, &todo.Location, &todo.DueDate,
			&todo.StartDate, &todo.CompletedAt, &todo.Status, &todo.PercentComplete,
			&todo.Priority, &todo.IsRecurring, &todo.RRule, &categoriesJSON,
			&alarmsJSON, &todo.ICalData, &todo.CreatedAt, &todo.UpdatedAt)
		if err != nil {
			return nil, err
		}

		todo.ID, _ = uuid.Parse(idStr)
		todo.CalendarID, _ = uuid.Parse(calIDStr)
		todo.AccountID, _ = uuid.Parse(accountIDStr)
		_ = json.Unmarshal([]byte(categoriesJSON), &todo.Categories)
		_ = json.Unmarshal([]byte(alarmsJSON), &todo.Alarms)

		todos = append(todos, &todo)
	}
	return todos, rows.Err()
}

func (r *SQLiteCalendarRepository) DeleteTodo(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM calendar_todos WHERE id = ?", id.String())
	return err
}
