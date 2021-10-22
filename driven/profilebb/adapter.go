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
	PII    *profileBBPII    `json:"pii"`
	NonPII *profileBBNonPII `json:"non_pii"`
}

type profileBBPII struct {
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

type profileBBNonPII struct {
	Over13               *bool               `json:"over13"`
	PrivacySettings      privacySettings     `json:"privacySettings"`
	Roles                []string            `json:"roles"`
	Interests            []interest          `json:"interests"`
	PositiveInterestTags []string            `json:"positiveInterestTags"`
	NegativeInterestTags []string            `json:"negativeInterestTags"`
	Favorites            map[string][]string `json:"favorites"`
	RegisteredVoter      *bool               `json:"registered_voter"`
	VotePlace            string              `json:"vote_place"`
	VoterByMail          *bool               `json:"voter_by_mail"`
	Voted                *bool               `json:"voted"`
	CreationDate         string              `json:"creationDate"`
	LastModifiedDate     string              `json:"lastModifiedDate"`
}

func (p *profileBBNonPII) convertInterests() map[string][]string {
	interestMap := map[string][]string{}
	for _, val := range p.Interests {
		if len(val.Category) > 0 {
			interestMap[val.Category] = val.Subcategories
		}
	}
	return interestMap
}

func (p *profileBBNonPII) convertTags() map[string]bool {
	tagsMap := map[string]bool{}
	for _, val := range p.PositiveInterestTags {
		tagsMap[val] = true
	}
	for _, val := range p.NegativeInterestTags {
		tagsMap[val] = false
	}
	return tagsMap
}

func (p *profileBBNonPII) convertVoter() map[string]interface{} {
	voter := map[string]interface{}{
		"vote_place": p.VotePlace,
	}

	if p.RegisteredVoter != nil {
		voter["registered_voter"] = *p.RegisteredVoter
	}

	if p.VoterByMail != nil {
		voter["voter_by_mail"] = *p.VoterByMail
	}

	if p.Voted != nil {
		voter["voted"] = *p.Voted
	}

	return voter
}

type privacySettings struct {
	Level int `json:"level"`
}

type interest struct {
	Category      string   `json:"category"`
	Subcategories []string `json:"subcategories"`
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

	req.Header.Set("ROKWIRE-CORE-BB-API-KEY", a.apiKey)

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

	preferences := a.reformatPreferences(profileData.NonPII, l)

	return &existingProfile, preferences, nil
}

func (a *Adapter) reformatPreferences(nonPII *profileBBNonPII, l *logs.Log) map[string]interface{} {
	if nonPII == nil {
		return nil
	}

	preferences := map[string]interface{}{
		"privacy_level": nonPII.PrivacySettings.Level,
		"roles":         nonPII.Roles,
		"favorites":     nonPII.Favorites,
		"interests":     nonPII.convertInterests(),
		"tags":          nonPII.convertTags(),
		"voter":         nonPII.convertVoter(),
		"over13":        nonPII.Over13,
	}

	dateCreated, err := parseTime(nonPII.CreationDate)
	if err != nil {
		l.WarnAction(logutils.ActionParse, "date created", err)
		preferences["date_created"] = time.Now()
	} else {
		preferences["date_created"] = dateCreated
	}

	dateUpdated, err := parseTime(nonPII.LastModifiedDate)
	if err != nil {
		l.WarnAction(logutils.ActionParse, "date updated", err)
		preferences["date_updated"] = time.Now()
	} else {
		preferences["date_updated"] = dateUpdated
	}

	return preferences
}

func parseTime(timeString string) (*time.Time, error) {
	parsedTime, err := time.Parse("2006-01-02T15:04:05.000Z", timeString)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, "date", nil, err)
	}
	return &parsedTime, nil
}

//NewProfileBBAdapter creates a new profile building block adapter instance
func NewProfileBBAdapter(profileHost string, apiKey string) *Adapter {
	return &Adapter{host: profileHost, apiKey: apiKey}
}
