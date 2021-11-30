package utils

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"net/http"
	"reflect"

	"github.com/rokwire/logging-library-go/logs"

	"github.com/rokwire/logging-library-go/errors"
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
)

// SetRandomSeed sets the seed for random number generation
func SetRandomSeed() error {
	seed := make([]byte, 8)
	_, err := crand.Read(seed)
	if err != nil {
		return errors.WrapErrorAction("generating", "math/rand seed", nil, err)
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

// ConvertToJSON converts to json
func ConvertToJSON(data interface{}) ([]byte, error) {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, errors.WrapErrorAction("error converting map to json", "", nil, err)
	}
	return dataJSON, nil
}

//DeepEqual checks whether a and b are ``deeply equal,''
func DeepEqual(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}

//SetStringIfEmpty returns b if a is empty, a if not
func SetStringIfEmpty(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

//GetType returns a string representing the type of data
func GetType(data interface{}) string {
	return reflect.TypeOf(data).String()
}

//GetIP extracts the IP address from the http request
func GetIP(l *logs.Log, r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}
