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

package auth_test

import (
	"testing"
)

//Email

func TestSignUp(t *testing.T) {
	// storage := genmocks.Storage{}
	// auth, err := auth.NewAuth(serviceID, host, authPrivKey, storage, emailer, minTokenExp, maxTokenExp, twilioAccountSID, twilioToken, twilioServiceSID, profileBBAdapter, smtpHost, smtpPortNum, smtpUser, smtpPassword, smtpFrom, logger)

	//TODO: auth.applySignUp (3) vs. emailAuthImpl.signUp (2), sent verification email only in sendVerifyCredential, not signUp
	type args struct {
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{}, wantErr: false},
		{name: "mismatched passwords", args: args{}, wantErr: true},
		{name: "existing account", args: args{}, wantErr: false},
		{name: "sent verification email", args: args{}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}
