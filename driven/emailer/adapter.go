package emailer

import (
	"strings"

	"gopkg.in/gomail.v2"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	typeMail logutils.MessageDataType = "mail"
)

//Adapter implements the Emailer interface
type Adapter struct {
	smptHost     string
	smtpPortNum  int
	smtpUser     string
	smtpPassword string
	smtpFrom     string
	emailDialer  *gomail.Dialer
}

//Send is used to send verification and password reset emails using Smtp connection
func (a *Adapter) Send(toEmail string, subject string, body string, attachmentFilename *string) error {
	if a.emailDialer == nil {
		return errors.New("email dialer is nil")
	}
	if toEmail == "" {
		return errors.New("missing email addresses")
	}

	emails := strings.Split(toEmail, ",")

	m := gomail.NewMessage()
	m.SetHeader("From", a.smtpFrom)
	m.SetHeader("To", emails...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)
	if attachmentFilename != nil {
		m.Attach(*attachmentFilename)
	}

	if err := a.emailDialer.DialAndSend(m); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, typeMail, nil, err)
	}
	return nil
}

//NewEmailerAdapter creates a new emailer adapter instance
func NewEmailerAdapter(smtpHost string, smtpPortNum int, smtpUser string, smtpPassword string, smtpFrom string) *Adapter {
	emailDialer := gomail.NewDialer(smtpHost, smtpPortNum, smtpUser, smtpPassword)

	return &Adapter{smptHost: smtpHost, smtpPortNum: smtpPortNum, smtpUser: smtpUser, smtpPassword: smtpPassword, smtpFrom: smtpFrom, emailDialer: emailDialer}
}
