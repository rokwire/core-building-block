package profilebb

import (
	"core-building-block/core/model"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//Adapter implements the ProfileBuildingBlock interface
type Adapter struct {
	host   string
	apiKey string
}

type profileBBData struct {
	PII    *profileBBPii          `json:"pii"`
	NonPII map[string]interface{} `json:"non_pii"`
}

type profileBBPii struct {
	LastName  string `json:"lastname"`
	FirstName string `json:"firstname"`
	Phone     string `json:"phone"`
	Email     string `json:"email"`
	BirthYear int16  `json:"birthYear"`
	Address   string `json:"address"`
	ZipCode   string `json:"zipCode"`
	State     string `json:"state"`
	Country   string `json:"country"`

	DateCreated string `json:"creationDate"`
}

//GetProfileBBData gets profile data by queryParams
func (a *Adapter) GetProfileBBData(queryParams map[string]string, l *logs.Log) (*model.Profile, map[string]interface{}, error) {
	if a.host == "" || a.apiKey == "" {
		return nil, nil, nil
	}

	query := url.Values{}
	for k, v := range queryParams {
		query.Set(k, v)
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, a.host+"/core?"+query.Encode(), nil)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}

	req.Header.Set("ROKWIRE-CBB-API-KEY", a.apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponse, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	if len(body) == 0 {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeResponseBody, nil)
	}

	var profileData profileBBData
	err = json.Unmarshal(body, &profileData)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.TypeResponseBody, nil, err)
	}

	if profileData.PII == nil {
		return nil, nil, nil
	}

	dateCreated, err := time.Parse("2006-01-02T15:04:05.000Z", profileData.PII.DateCreated)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionParse, logutils.TypeString, &logutils.FieldArgs{"creationDate": profileData.PII.DateCreated}, err)
	}
	existingProfile := model.Profile{FirstName: profileData.PII.FirstName, LastName: profileData.PII.LastName,
		Email: profileData.PII.Email, Phone: profileData.PII.Phone, BirthYear: profileData.PII.BirthYear,
		Address: profileData.PII.Address, ZipCode: profileData.PII.ZipCode, State: profileData.PII.State,
		Country: profileData.PII.Country, DateCreated: dateCreated}

	if profileData.NonPII != nil {
		if creationDate, ok := profileData.NonPII["creationDate"].(string); ok {
			dateCreated, err := time.Parse("2006-01-02T15:04:05.000Z", creationDate)
			if err != nil {
				l.WarnAction(logutils.ActionParse, logutils.TypeString, err)
			} else {
				profileData.NonPII["date_created"] = dateCreated
				delete(profileData.NonPII, "creationDate")
			}
		}
		if lastModifiedDate, ok := profileData.NonPII["lastModifiedDate"].(string); ok {
			dateUpdated, err := time.Parse("2006-01-02T15:04:05.000Z", lastModifiedDate)
			if err != nil {
				l.WarnAction(logutils.ActionParse, logutils.TypeString, err)
			} else {
				profileData.NonPII["date_updated"] = dateUpdated
				delete(profileData.NonPII, "lastModifiedDate")
			}
		}
	}

	return &existingProfile, profileData.NonPII, nil
}

//NewProfileBBAdapter creates a new profile building block adapter instance
func NewProfileBBAdapter(profileHost string, apiKey string) *Adapter {
	return &Adapter{host: profileHost, apiKey: apiKey}
}
