package filter

import "github.com/google/uuid"

// DefaultRules provides common pre-built filter rules
var DefaultRules = []Rule{
	{
		Name:        "Block Executable Attachments",
		Description: "Blocks emails with potentially dangerous executable attachments",
		Priority:    10,
		MatchType:   MatchAny,
		Conditions: []Condition{
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".exe"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".bat"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".cmd"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".scr"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".pif"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".vbs"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".js"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".jar"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".msi"},
			{Field: FieldAttachment, Operator: OpEndsWith, Value: ".dll"},
		},
		Actions: []Action{
			{Type: ActionQuarantine, Params: ActionParams{"reason": "dangerous_attachment"}},
			{Type: ActionNotify, Params: ActionParams{"admin": true}},
		},
		IsActive:    true,
		StopOnMatch: true,
	},
	{
		Name:        "Block Archive with Executables",
		Description: "Blocks password-protected archives and archives containing executables",
		Priority:    15,
		MatchType:   MatchAny,
		Conditions: []Condition{
			{Field: FieldAttachment, Operator: OpMatches, Value: `\.(zip|rar|7z|tar)$`},
		},
		Actions: []Action{
			{Type: ActionAddHeader, Params: ActionParams{"name": "X-Archive-Warning", "value": "Contains archive attachment"}},
		},
		IsActive:    true,
		StopOnMatch: false,
	},
	{
		Name:        "SPF Fail - Quarantine",
		Description: "Quarantine emails that fail SPF authentication",
		Priority:    20,
		MatchType:   MatchAll,
		Conditions: []Condition{
			{Field: FieldSPFResult, Operator: OpEquals, Value: "fail"},
		},
		Actions: []Action{
			{Type: ActionQuarantine, Params: ActionParams{"reason": "spf_fail"}},
			{Type: ActionAddHeader, Params: ActionParams{"name": "X-SPF-Status", "value": "FAIL"}},
		},
		IsActive:    true,
		StopOnMatch: false,
	},
	{
		Name:        "DMARC Reject Policy",
		Description: "Reject emails that fail DMARC with reject policy",
		Priority:    25,
		MatchType:   MatchAll,
		Conditions: []Condition{
			{Field: FieldDMARCResult, Operator: OpEquals, Value: "reject"},
		},
		Actions: []Action{
			{Type: ActionReject, Params: ActionParams{"code": 550, "message": "DMARC policy violation"}},
		},
		IsActive:    true,
		StopOnMatch: true,
	},
	{
		Name:        "High Spam Score",
		Description: "Quarantine high spam score emails",
		Priority:    30,
		MatchType:   MatchAll,
		Conditions: []Condition{
			{Field: FieldSpamScore, Operator: OpGreaterThan, Value: "5.0"},
		},
		Actions: []Action{
			{Type: ActionMove, Params: ActionParams{"folder": "Junk"}},
			{Type: ActionSetFlag, Params: ActionParams{"flag": "\\Junk"}},
		},
		IsActive:    true,
		StopOnMatch: false,
	},
	{
		Name:        "Very High Spam Score",
		Description: "Discard very high spam score emails",
		Priority:    29,
		MatchType:   MatchAll,
		Conditions: []Condition{
			{Field: FieldSpamScore, Operator: OpGreaterThan, Value: "10.0"},
		},
		Actions: []Action{
			{Type: ActionDiscard},
		},
		IsActive:    true,
		StopOnMatch: true,
	},
	{
		Name:        "Large Email Warning",
		Description: "Add warning header for large emails",
		Priority:    100,
		MatchType:   MatchAll,
		Conditions: []Condition{
			{Field: FieldSize, Operator: OpGreaterThan, Value: "10485760"}, // 10MB
		},
		Actions: []Action{
			{Type: ActionAddHeader, Params: ActionParams{"name": "X-Large-Email", "value": "true"}},
		},
		IsActive:    true,
		StopOnMatch: false,
	},
}

// GetDefaultRulesForOrg returns default rules with org ID set
func GetDefaultRulesForOrg(orgID uuid.UUID) []Rule {
	rules := make([]Rule, len(DefaultRules))
	for i, r := range DefaultRules {
		rules[i] = r
		rules[i].ID = uuid.New()
		rules[i].OrgID = orgID
	}
	return rules
}

// SpamKeywords contains common spam keywords
var SpamKeywords = []string{
	"viagra", "cialis", "lottery", "winner", "nigerian prince",
	"wire transfer", "bank account", "urgent response",
	"million dollars", "inheritance", "claim your prize",
	"act now", "limited time", "exclusive deal",
	"click here", "unsubscribe", "opt out",
}

// PhishingPatterns contains common phishing patterns
var PhishingPatterns = []string{
	`(?i)verify.*account`,
	`(?i)confirm.*identity`,
	`(?i)suspend.*account`,
	`(?i)unusual.*activity`,
	`(?i)security.*alert`,
	`(?i)update.*payment`,
	`(?i)expire.*password`,
	`(?i)click.*link.*below`,
	`(?i)dear.*customer`,
	`(?i)dear.*user`,
}
