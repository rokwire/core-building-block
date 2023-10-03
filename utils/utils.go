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

package utils

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/rokwire/core-auth-library-go/v3/keys"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"

	"github.com/rokwire/logging-library-go/v2/errors"
)

const (
	//ErrorStatusAlreadyExists ...
	ErrorStatusAlreadyExists string = "already-exists"
	//ErrorStatusNotFound ...
	ErrorStatusNotFound string = "not-found"
	//ErrorStatusInvalid ...
	ErrorStatusInvalid string = "invalid"
	//ErrorStatusUnverified ...
	ErrorStatusUnverified string = "unverified"
	//ErrorStatusVerificationExpired ...
	ErrorStatusVerificationExpired string = "verification-expired"
	//ErrorStatusSharedCredentialUnverified ...
	ErrorStatusSharedCredentialUnverified string = "shared-credential-unverified"
	//ErrorStatusNotAllowed ...
	ErrorStatusNotAllowed string = "not-allowed"
	//ErrorStatusUsernameTaken ...
	ErrorStatusUsernameTaken string = "username-taken"

	//Character sets for password generation
	upper   string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   string = "abcdefghijklmnopqrstuvwxyz"
	digits  string = "0123456789"
	special string = "!@#$%^&*()"
)

// SetRandomSeed sets the seed for random number generation
func SetRandomSeed() error {
	seed := make([]byte, 8)
	_, err := crand.Read(seed)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionGenerate, "math/rand seed", nil, err)
	}

	rand.Seed(int64(binary.LittleEndian.Uint64(seed)))
	return nil
}

// GenerateRandomBytes returns securely generated random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded securely generated random string
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

// GenerateRandomInt returns a random integer between 0 and max
func GenerateRandomInt(max int) int {
	return rand.Intn(max)
}

// GenerateRandomPassword returns a randomly generated password string
func GenerateRandomPassword(s int) string {
	validCharacters := []byte(upper + lower + digits + special)
	rand.Shuffle(len(validCharacters), func(i, j int) { validCharacters[i], validCharacters[j] = validCharacters[j], validCharacters[i] })

	password := make([]byte, s)
	for i := 0; i < s; i++ {
		password[i] = validCharacters[rand.Intn(len(validCharacters))]
	}

	return string(password)
}

// ConvertToJSON converts to json
func ConvertToJSON(data interface{}) ([]byte, error) {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "map to json", nil, err)
	}
	return dataJSON, nil
}

// DeepEqual checks whether a and b are “deeply equal,”
func DeepEqual(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}

// SetStringIfEmpty returns b if a is empty, a if not
func SetStringIfEmpty(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

// GetType returns a string representing the type of data
func GetType(data interface{}) string {
	return reflect.TypeOf(data).String()
}

// GetIP extracts the IP address from the http request
func GetIP(l *logs.Log, r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	l.AddContext("ip_address", IPAddress)
	return IPAddress
}

// SHA256Hash computes the SHA256 hash of a byte slice
func SHA256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// GetLogValue prepares a sensitive data to be logged.
func GetLogValue(value string, n int) string {
	if len(value) <= n {
		return "***"
	}
	lastN := value[len(value)-n:]
	return fmt.Sprintf("***%s", lastN)
}

// FormatTime formats the time value which this pointer points. Gives empty string if the pointer is nil
func FormatTime(v *time.Time) string {
	if v == nil {
		return ""
	}
	return v.Format("2006-01-02T15:04:05.000Z")
}

// Contains checks if list contains value
func Contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// StringListDiff returns a list of added, removed, unchanged values between a new and old string list
func StringListDiff(new []string, old []string) ([]string, []string, []string) {
	added := []string{}
	removed := []string{}
	unchanged := []string{}
	for _, newVal := range new {
		if !Contains(old, newVal) {
			added = append(added, newVal)
		} else {
			unchanged = append(unchanged, newVal)
		}
	}
	for _, oldVal := range old {
		if !Contains(new, oldVal) {
			removed = append(removed, oldVal)
		}
	}
	return added, removed, unchanged
}

// StringPrefixes returns a list of all prefixes of s delimited by sep, including s itself
func StringPrefixes(s string, sep string) []string {
	subStrings := strings.Split(s, sep)
	prefixes := make([]string, len(subStrings))
	for i := 1; i <= len(subStrings); i++ {
		prefixes[i-1] = strings.Join(subStrings[0:i], sep)
	}
	return prefixes
}

// StringOrNil returns a pointer to the input string, but returns nil if input matches nilVal
func StringOrNil(v string, nilVal string) *string {
	if v == nilVal {
		return nil
	}
	return &v
}

// GetPrintableString returns the string content of a pointer, and defaultVal if pointer is nil
func GetPrintableString(v *string, defaultVal string) string {
	if v != nil {
		return *v
	}
	return defaultVal
}

// Encrypt data with AES-128 encryption algorithm and returns the encrypted data and the AES key encrypted with the given public key
func Encrypt(data []byte, pub *keys.PubKey) (string, string, string, error) {
	blockSize := 16
	randomKey, err := GenerateRandomBytes(blockSize)
	if err != nil {
		return "", "", "", errors.WrapErrorAction("generating", "random bytes", logutils.StringArgs("session key"), err)
	}
	//Encrypt blobJSON with AES using random key(CBC mode, PKCS7 padding, 0 IV) and convert to base 64 to get encrypted_data
	cipherBlock, err := aes.NewCipher(randomKey)
	if err != nil {
		return "", "", "", errors.WrapErrorAction(logutils.ActionCreate, "AES cipher block", nil, err)
	}

	nonce, err := GenerateRandomBytes(12)
	if err != nil {
		return "", "", "", errors.WrapErrorAction("generating", "random bytes", logutils.StringArgs("nonce"), err)
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", "", "", errors.WrapErrorAction(logutils.ActionCreate, "block cipher", logutils.StringArgs("GCM"), err)
	}
	cipherText := gcm.Seal(nil, nonce, data, nil)

	//Encrypt the session key with public key
	encryptedKeyBytes, err := EncryptWithPublicKey(randomKey, pub)
	if err != nil || encryptedKeyBytes == nil {
		return "", "", "", err
	}
	encodedKey := base64.StdEncoding.EncodeToString(encryptedKeyBytes)
	encodedNonce := base64.StdEncoding.EncodeToString(nonce)
	encodedData := base64.StdEncoding.EncodeToString(cipherText)
	return encodedKey, encodedNonce, encodedData, nil
}

// EncryptWithPublicKey encrypts data with the given public key
func EncryptWithPublicKey(data []byte, pub *keys.PubKey) ([]byte, error) {
	cipherText, err := pub.Encrypt(data, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionEncrypt, logutils.TypeString, logutils.StringArgs("public key"), err)
	}
	return cipherText, nil
}

// Decrypt decrypts data using AES-128 with the key decrypted using priv
func Decrypt(data string, key string, nonce string, priv *keys.PrivKey) ([]byte, error) {
	//1. decrypt key
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDecode, "key string", nil, err)
	}
	decryptedKey, err := DecryptWithPrivateKey(decodedKey, priv)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDecrypt, "decoded key string", nil, err)
	}

	//2. decrypt data
	decodedNonce, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDecode, "iv string", nil, err)
	}
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDecode, "data string", nil, err)
	}
	cipherBlock, err := aes.NewCipher(decryptedKey)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "AES cipher block", nil, err)
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "block cipher", logutils.StringArgs("GCM"), err)
	}
	decryptedData, err := gcm.Open(nil, decodedNonce, decodedData, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDecrypt, "decoded data string", nil, err)
	}

	return decryptedData, nil
}

// DecryptWithPrivateKey decrypts data with the given private key
func DecryptWithPrivateKey(data []byte, priv *keys.PrivKey) ([]byte, error) {
	cipherText, err := priv.Decrypt(data, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionDecrypt, logutils.TypeString, logutils.StringArgs("private key"), err)
	}
	return []byte(cipherText), nil
}

// StartTimer starts a timer with the given name, period, and function to call when the timer goes off
func StartTimer(timer *time.Timer, timerDone chan bool, period time.Duration, periodicFunc func(), name string, logger *logs.Logger) {
	if logger != nil {
		logger.Info("start timer for " + name)
	}

	//cancel if active
	if timer != nil {
		timerDone <- true
		timer.Stop()
	}

	onTimer(timer, timerDone, period, periodicFunc, name, logger)
}

func onTimer(timer *time.Timer, timerDone chan bool, period time.Duration, periodicFunc func(), name string, logger *logs.Logger) {
	if logger != nil {
		logger.Info(name)
	}

	periodicFunc()

	timer = time.NewTimer(period)
	select {
	case <-timer.C:
		// timer expired
		timer = nil

		onTimer(timer, timerDone, period, periodicFunc, name, logger)
	case <-timerDone:
		// timer aborted
		timer = nil
	}
}
