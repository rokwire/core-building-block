package sender

import (
	"strings"

	"gopkg.in/gomail.v2"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	typeMail logutils.MessageDataType = "mail"
)

//EmailAdapter implements the Sender interface
type EmailAdapter struct {
	smptHost     string
	smtpPort     string
	smtpUser     string
	smtpPassword string
	smtpFrom     string
	emailDialer  *gomail.Dialer

	from string
	to   []string
}

//SendEmail is used to send verification and password reset emails using Smtp connection
func (a *EmailAdapter) SendEmail(toEmail string, subject string, body string, attachmentFilename string) error {
	if a.emailDialer == nil {
		return errors.New("email Dialer is nil")
	}
	if toEmail == "" {
		return errors.New("Missing email addresses")
	}

	emails := strings.Split(toEmail, ",")

	m := gomail.NewMessage()
	m.SetHeader("From", a.smtpFrom)
	m.SetHeader("To", emails...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)
	m.Attach(attachmentFilename)

	if err := a.emailDialer.DialAndSend(m); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, typeMail, nil, err)
	}
	return nil
}

//NewSenderAdapter creates a new sender adapter instance
func NewEmailSenderAdapter(smtpHost string, smtpPort string, smtpUser string, smtpPassword string, smtpFrom string) *EmailAdapter {
	return &EmailAdapter{smptHost: smtpHost, smtpPort: smtpPort, smtpUser: smtpUser, smtpPassword: smtpPassword, smtpFrom: smtpFrom}
}
