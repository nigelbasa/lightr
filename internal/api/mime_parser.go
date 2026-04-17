package api

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"

	"github.com/google/uuid"
)

// ParsedMessage contains decoded email content
type ParsedMessage struct {
	Text        string           `json:"text"`
	HTML        string           `json:"html"`
	Attachments []AttachmentMeta `json:"attachments"`
}

// AttachmentMeta contains attachment metadata without the data
type AttachmentMeta struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Inline      bool   `json:"inline"`
	ContentID   string `json:"content_id,omitempty"`
}

// AttachmentData contains the actual attachment content
type AttachmentData struct {
	Meta AttachmentMeta
	Data []byte
}

// ParseRFC822Message parses a raw RFC822 email and extracts text, HTML, and attachment metadata
func ParseRFC822Message(rawEmail []byte) (*ParsedMessage, []AttachmentData) {
	result := &ParsedMessage{
		Attachments: []AttachmentMeta{},
	}
	var attachments []AttachmentData

	msg, err := mail.ReadMessage(bytes.NewReader(rawEmail))
	if err != nil {
		// Fallback: return the raw content as text
		return &ParsedMessage{Text: string(rawEmail)}, nil
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Simple message, no MIME
		body, _ := io.ReadAll(msg.Body)
		encoding := msg.Header.Get("Content-Transfer-Encoding")
		decoded := decodeTransferEncodingAPI(body, encoding)
		result.Text = string(decoded)
		return result, nil
	}

	// Non-multipart message
	if !strings.HasPrefix(mediaType, "multipart/") {
		body, _ := io.ReadAll(msg.Body)
		encoding := msg.Header.Get("Content-Transfer-Encoding")
		decoded := decodeTransferEncodingAPI(body, encoding)

		if strings.Contains(mediaType, "text/html") {
			result.HTML = string(decoded)
		} else {
			result.Text = string(decoded)
		}
		return result, nil
	}

	// Multipart message
	boundary := params["boundary"]
	if boundary == "" {
		return result, nil
	}

	body, _ := io.ReadAll(msg.Body)
	parseMultipart(boundary, body, result, &attachments, 0)

	return result, attachments
}

// parseMultipart recursively parses multipart content
func parseMultipart(boundary string, body []byte, result *ParsedMessage, attachments *[]AttachmentData, depth int) {
	if depth > 10 {
		return // Prevent infinite recursion
	}

	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		partContentType := part.Header.Get("Content-Type")
		if partContentType == "" {
			partContentType = "text/plain"
		}
		partMediaType, partParams, _ := mime.ParseMediaType(partContentType)
		partEncoding := part.Header.Get("Content-Transfer-Encoding")
		partDisposition := part.Header.Get("Content-Disposition")
		contentID := part.Header.Get("Content-ID")

		// Clean Content-ID (remove angle brackets)
		contentID = strings.Trim(contentID, "<>")

		partBody, _ := io.ReadAll(part)

		// Check for nested multipart
		if strings.HasPrefix(partMediaType, "multipart/") {
			nestedBoundary := partParams["boundary"]
			if nestedBoundary != "" {
				parseMultipart(nestedBoundary, partBody, result, attachments, depth+1)
			}
			continue
		}

		// Decode content
		decoded := decodeTransferEncodingAPI(partBody, partEncoding)

		// Determine if this is an attachment
		_, dispParams, _ := mime.ParseMediaType(partDisposition)
		filename := dispParams["filename"]
		if filename == "" {
			filename = partParams["name"]
		}

		isAttachment := strings.Contains(strings.ToLower(partDisposition), "attachment")
		isInline := strings.Contains(strings.ToLower(partDisposition), "inline")

		// If it has a filename or is not text, treat as attachment
		if filename != "" || (isAttachment && !strings.HasPrefix(partMediaType, "text/")) {
			attID := uuid.New().String()
			meta := AttachmentMeta{
				ID:          attID,
				Filename:    filename,
				ContentType: partMediaType,
				Size:        int64(len(decoded)),
				Inline:      isInline || contentID != "",
				ContentID:   contentID,
			}
			result.Attachments = append(result.Attachments, meta)
			*attachments = append(*attachments, AttachmentData{
				Meta: meta,
				Data: decoded,
			})
			continue
		}

		// Handle inline images without Content-Disposition
		if strings.HasPrefix(partMediaType, "image/") {
			attID := uuid.New().String()
			if filename == "" {
				filename = "image"
			}
			meta := AttachmentMeta{
				ID:          attID,
				Filename:    filename,
				ContentType: partMediaType,
				Size:        int64(len(decoded)),
				Inline:      true,
				ContentID:   contentID,
			}
			result.Attachments = append(result.Attachments, meta)
			*attachments = append(*attachments, AttachmentData{
				Meta: meta,
				Data: decoded,
			})
			continue
		}

		// Text content - prefer HTML over plain text
		if strings.EqualFold(partMediaType, "text/html") {
			if result.HTML == "" || len(decoded) > len(result.HTML) {
				result.HTML = string(decoded)
			}
		} else if strings.EqualFold(partMediaType, "text/plain") {
			if result.Text == "" {
				result.Text = string(decoded)
			}
		}
	}
}

// decodeTransferEncodingAPI decodes content based on Content-Transfer-Encoding
func decodeTransferEncodingAPI(data []byte, encoding string) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		// Remove line breaks before decoding
		cleaned := strings.ReplaceAll(string(data), "\r\n", "")
		cleaned = strings.ReplaceAll(cleaned, "\n", "")
		cleaned = strings.TrimSpace(cleaned)
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			// Try with padding
			for len(cleaned)%4 != 0 {
				cleaned += "="
			}
			decoded, err = base64.StdEncoding.DecodeString(cleaned)
			if err != nil {
				return data // Return original if decode fails
			}
		}
		return decoded
	case "quoted-printable":
		reader := quotedprintable.NewReader(bytes.NewReader(data))
		decoded, err := io.ReadAll(reader)
		if err != nil {
			return data
		}
		return decoded
	default:
		return data
	}
}
