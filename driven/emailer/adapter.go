// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package emailer

import (
	"strings"

	"gopkg.in/gomail.v2"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	typeMail logutils.MessageDataType = "mail"
)

// Adapter implements the Emailer interface
type Adapter struct {
	smptHost     string
	smtpPortNum  int
	smtpUser     string
	smtpPassword string
	smtpFrom     string
	emailDialer  *gomail.Dialer
}

// Send is used to send verification and password reset emails using Smtp connection
func (a *Adapter) Send(toEmail string, subject string, body string, attachmentFilename *string) error {
	if a.emailDialer == nil {
		return errors.ErrorData(logutils.StatusMissing, "email dialer", nil)
	}
	if toEmail == "" {
		return errors.ErrorData(logutils.StatusMissing, "email addresses", nil)
	}

	emails := strings.Split(toEmail, ",")

	m := gomail.NewMessage()
	m.SetHeader("From", a.smtpFrom)
	m.SetHeader("To", emails...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)
	if attachmentFilename != nil {
		m.Attach(*attachmentFilename)
	}

	if err := a.emailDialer.DialAndSend(m); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, typeMail, nil, err)
	}
	return nil
}

// NewEmailerAdapter creates a new emailer adapter instance
func NewEmailerAdapter(smtpHost string, smtpPortNum int, smtpUser string, smtpPassword string, smtpFrom string) *Adapter {
	emailDialer := gomail.NewDialer(smtpHost, smtpPortNum, smtpUser, smtpPassword)

	return &Adapter{smptHost: smtpHost, smtpPortNum: smtpPortNum, smtpUser: smtpUser, smtpPassword: smtpPassword, smtpFrom: smtpFrom, emailDialer: emailDialer}
}
