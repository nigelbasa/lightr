package template

// DefaultTemplates provides built-in email templates
var DefaultTemplates = map[string]*Template{
	"welcome": {
		Name:        "welcome",
		Description: "Welcome email for new users",
		Category:    "transactional",
		Subject:     "Welcome to {{.company_name}}, {{.first_name}}!",
		HTMLBody: `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: {{.brand_color | default "#4F46E5"}}; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #fff; padding: 30px; border: 1px solid #e5e7eb; border-top: none; }
        .button { display: inline-block; background: {{.brand_color | default "#4F46E5"}}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to {{.company_name}}!</h1>
        </div>
        <div class="content">
            <p>Hi {{.first_name}},</p>
            <p>Thank you for signing up! We're excited to have you on board.</p>
            {{if .verification_url}}
            <p>Please verify your email address by clicking the button below:</p>
            <a href="{{.verification_url}}" class="button">Verify Email</a>
            {{end}}
            <p>If you have any questions, feel free to reply to this email.</p>
            <p>Best regards,<br>The {{.company_name}} Team</p>
        </div>
        <div class="footer">
            <p>&copy; {{.year}} {{.company_name}}. All rights reserved.</p>
            {{if .unsubscribe_url}}<p><a href="{{.unsubscribe_url}}">Unsubscribe</a></p>{{end}}
        </div>
    </div>
</body>
</html>`,
		TextBody: `Welcome to {{.company_name}}!

Hi {{.first_name}},

Thank you for signing up! We're excited to have you on board.

{{if .verification_url}}Please verify your email by visiting: {{.verification_url}}{{end}}

If you have any questions, feel free to reply to this email.

Best regards,
The {{.company_name}} Team`,
		Variables: []TemplateVar{
			{Name: "first_name", Description: "User's first name", Required: true},
			{Name: "company_name", Description: "Company name", Required: true},
			{Name: "verification_url", Description: "Email verification URL", Required: false},
			{Name: "brand_color", Description: "Brand color hex code", Default: "#4F46E5"},
			{Name: "year", Description: "Current year", Default: "2024"},
		},
		IsActive: true,
	},

	"password_reset": {
		Name:        "password_reset",
		Description: "Password reset request email",
		Category:    "transactional",
		Subject:     "Reset your {{.company_name}} password",
		HTMLBody: `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .content { background: #fff; padding: 30px; border: 1px solid #e5e7eb; border-radius: 8px; }
        .button { display: inline-block; background: #DC2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .warning { background: #FEF3C7; border: 1px solid #F59E0B; padding: 15px; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <h2>Password Reset Request</h2>
            <p>Hi {{.first_name | default "there"}},</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <a href="{{.reset_url}}" class="button">Reset Password</a>
            <div class="warning">
                <strong>⚠️ Security Notice:</strong> This link expires in {{.expires_in | default "1 hour"}}. If you didn't request this, please ignore this email or contact support.
            </div>
            <p>For security, this request was received from:<br>
            IP: {{.ip_address}}<br>
            Time: {{.request_time}}</p>
        </div>
        <div class="footer">
            <p>&copy; {{.year}} {{.company_name}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`,
		TextBody: `Password Reset Request

Hi {{.first_name | default "there"}},

We received a request to reset your password. Visit the link below to create a new password:

{{.reset_url}}

This link expires in {{.expires_in | default "1 hour"}}.

If you didn't request this, please ignore this email or contact support.

For security, this request was received from:
IP: {{.ip_address}}
Time: {{.request_time}}`,
		Variables: []TemplateVar{
			{Name: "reset_url", Description: "Password reset URL", Required: true},
			{Name: "first_name", Description: "User's first name", Required: false},
			{Name: "company_name", Description: "Company name", Required: true},
			{Name: "expires_in", Description: "Link expiration time", Default: "1 hour"},
			{Name: "ip_address", Description: "Request IP address", Required: false},
			{Name: "request_time", Description: "Request timestamp", Required: false},
		},
		IsActive: true,
	},

	"invoice": {
		Name:        "invoice",
		Description: "Invoice email with payment details",
		Category:    "transactional",
		Subject:     "Invoice #{{.invoice_number}} from {{.company_name}}",
		HTMLBody: `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { border-bottom: 2px solid #e5e7eb; padding-bottom: 20px; margin-bottom: 20px; }
        .invoice-details { background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        th { background: #f3f4f6; }
        .total { font-size: 18px; font-weight: bold; }
        .button { display: inline-block; background: #059669; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; }
        .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Invoice #{{.invoice_number}}</h1>
            <p>Date: {{.invoice_date}}</p>
        </div>
        <div class="invoice-details">
            <p><strong>Bill To:</strong><br>
            {{.customer_name}}<br>
            {{.customer_email}}</p>
            <p><strong>Due Date:</strong> {{.due_date}}</p>
        </div>
        <table>
            <tr>
                <th>Description</th>
                <th>Qty</th>
                <th>Price</th>
                <th>Total</th>
            </tr>
            {{range .line_items}}
            <tr>
                <td>{{.description}}</td>
                <td>{{.quantity}}</td>
                <td>{{.unit_price}}</td>
                <td>{{.total}}</td>
            </tr>
            {{end}}
            <tr class="total">
                <td colspan="3">Total</td>
                <td>{{.total_amount}}</td>
            </tr>
        </table>
        {{if .payment_url}}
        <p><a href="{{.payment_url}}" class="button">Pay Now</a></p>
        {{end}}
        <div class="footer">
            <p>{{.company_name}}<br>{{.company_address}}</p>
        </div>
    </div>
</body>
</html>`,
		Variables: []TemplateVar{
			{Name: "invoice_number", Description: "Invoice number", Required: true},
			{Name: "invoice_date", Description: "Invoice date", Required: true},
			{Name: "due_date", Description: "Payment due date", Required: true},
			{Name: "customer_name", Description: "Customer name", Required: true},
			{Name: "customer_email", Description: "Customer email", Required: true},
			{Name: "line_items", Description: "Array of line items", Required: true},
			{Name: "total_amount", Description: "Total amount", Required: true},
			{Name: "payment_url", Description: "Payment URL", Required: false},
			{Name: "company_name", Description: "Company name", Required: true},
			{Name: "company_address", Description: "Company address", Required: false},
		},
		IsActive: true,
	},

	"notification": {
		Name:        "notification",
		Description: "General notification email",
		Category:    "notification",
		Subject:     "{{.subject}}",
		HTMLBody: `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .content { background: #fff; padding: 30px; border: 1px solid #e5e7eb; border-radius: 8px; }
        .icon { font-size: 48px; text-align: center; margin-bottom: 20px; }
        .button { display: inline-block; background: {{.button_color | default "#4F46E5"}}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            {{if .icon}}<div class="icon">{{.icon}}</div>{{end}}
            <h2>{{.title}}</h2>
            {{.message | nl2br}}
            {{if .action_url}}
            <p><a href="{{.action_url}}" class="button">{{.action_text | default "View Details"}}</a></p>
            {{end}}
        </div>
    </div>
</body>
</html>`,
		TextBody: `{{.title}}

{{.message}}

{{if .action_url}}{{.action_text | default "View Details"}}: {{.action_url}}{{end}}`,
		Variables: []TemplateVar{
			{Name: "subject", Description: "Email subject", Required: true},
			{Name: "title", Description: "Notification title", Required: true},
			{Name: "message", Description: "Notification message", Required: true},
			{Name: "icon", Description: "Emoji or icon", Required: false},
			{Name: "action_url", Description: "Action button URL", Required: false},
			{Name: "action_text", Description: "Action button text", Default: "View Details"},
		},
		IsActive: true,
	},
}

// GetDefaultTemplate returns a default template by name
func GetDefaultTemplate(name string) *Template {
	if t, ok := DefaultTemplates[name]; ok {
		return t
	}
	return nil
}

// ListDefaultTemplates returns all default template names
func ListDefaultTemplates() []string {
	names := make([]string, 0, len(DefaultTemplates))
	for name := range DefaultTemplates {
		names = append(names, name)
	}
	return names
}
