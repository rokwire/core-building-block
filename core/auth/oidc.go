package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/coreos/go-oidc"
	"golang.org/x/sync/syncmap"
)

//dynamic claimsMap

var uidClaimTag string = ""
var nameClaimTag string = ""
var firstNameClaimTag string = ""
var lastNameClaimTag string = ""
var emailClaimTag string = ""
var phoneClaimTag string = ""
var groupsClaimTag string = ""
var populationsClaimTag string = ""

// OIDC implementation of authType
type oidcAuthImpl struct {
	auth *Auth

	authInfo     *syncmap.Map //cache authInfo / client id -> authInfo
	authInfoLock *sync.RWMutex
}

type oidcCreds struct {
	ClientID string `json:"client_id"`
	Domain   string `json:"domain"`
	IDToken  string `json:"id_token"`
}

func (a *oidcAuthImpl) check(creds string) (*Claims, error) {
	var newCreds oidcCreds
	err := json.Unmarshal([]byte(creds), &newCreds)
	if err != nil {
		return nil, err
	}

	authInfo, err := a.auth.storage.FindDomainAuthInfo(newCreds.Domain)
	if err != nil {
		return nil, err
	}

	oidcProvider := authInfo.OIDCHost
	oidcAdminClientID := authInfo.OIDCClientID

	// Validate the token
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return nil, err
	}
	adminIDTokenVerifier := provider.Verifier(&oidc.Config{ClientID: oidcAdminClientID})
	idToken, err := adminIDTokenVerifier.Verify(context.Background(), newCreds.IDToken)
	if err != nil {
		return nil, err
	}

	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		log.Printf("error getting raw claims from token - %s\n", err)
	} else {
		log.Printf("Raw Token Claims: %v", rawClaims)
	}

	var claims Claims
	uidClaimTag = authInfo.Claims["uid"]
	nameClaimTag = authInfo.Claims["name"]
	firstNameClaimTag = authInfo.Claims["firstname"]
	lastNameClaimTag = authInfo.Claims["lastname"]
	emailClaimTag = authInfo.Claims["email"]
	phoneClaimTag = authInfo.Claims["phone"]
	groupsClaimTag = authInfo.Claims["groups"]
	populationsClaimTag = authInfo.Claims["populations"]
	log.Printf("AuthInfo Claims: %v", authInfo.Claims)

	if err := idToken.Claims(&claims); err != nil {
		log.Printf("error getting claims from token - %s\n", err)
		return nil, err
	}

	// populationsString := ""
	// inRequiredPopulation := (authInfo.RequiredPopulation == "")
	// if populations, ok := claims.Populations.([]interface{}); ok {
	// 	for _, populationInterface := range populations {
	// 		if population, ok := populationInterface.(string); ok {
	// 			if authInfo.RequiredPopulation == population {
	// 				inRequiredPopulation = true
	// 			}

	// 			if authInfo.Populations != nil {
	// 				if populationString, ok := authInfo.Populations[population]; ok {
	// 					if populationsString != "" {
	// 						populationsString += ","
	// 					}
	// 					populationsString += populationString
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	// if !inRequiredPopulation {
	// 	log.Printf("missing required population: %s - %v\n", authInfo.RequiredPopulation, claims.Populations)
	// 	return nil
	// }

	// claims.Populations = populationsString

	// var groups string
	// groupsMap := make(map[string]string)

	// for key, value := range authInfo.Groups {
	// 	groupsMap[value] = key
	// }
	// groupsSplit := strings.Split(*claims.Groups, ",")

	// for _, s := range groupsSplit {
	// 	if groups != "" {
	// 		groups += ", "
	// 	}
	// 	groups += groupsMap[s]
	// }
	// claims.Groups = &groups

	uidClaimTag = "uid"
	nameClaimTag = "name"
	emailClaimTag = "email"
	phoneClaimTag = "phone"
	groupsClaimTag = "groups"
	populationsClaimTag = "populations"

	return &claims, nil
}

func (a *oidcAuthImpl) loadAuthInfoDocs() error {
	//1 load
	authInfoDocs, err := a.auth.storage.LoadAuthInfoDocs()
	if err != nil {
		return err
	}

	//2 set
	a.setAuthInfo(authInfoDocs)

	return nil
}

func (a *oidcAuthImpl) getAuthInfo(domain string) *AuthInfo {
	a.authInfoLock.RLock()
	defer a.authInfoLock.RUnlock()

	var authInfo AuthInfo //to return

	item, _ := a.authInfo.Load(domain)
	if item != nil {
		authInfo = item.(AuthInfo)
	} else {
		log.Println("getAPIKey() -> nil for domain", domain)
	}

	return &authInfo
}

func (a *oidcAuthImpl) setAuthInfo(authInfo map[string]AuthInfo) {
	a.authInfoLock.Lock()
	defer a.authInfoLock.Unlock()

	//first clear the old data
	a.authInfo = &syncmap.Map{}

	for key, value := range authInfo {
		a.authInfo.Store(key, value)
	}
}

func (a *oidcAuthImpl) oidcLogin(code string, IDToken string) error {
	return errors.New("Unimplemented")
	// 1. Request Tokens
	// AuthToken newAuthToken = await _loadShibbolethAuthTokenWithCode(code, idToken: idToken);
	// if (newAuthToken == null) {
	//   // fail
	// }

	// // 2. Request rokwire access token
	// RokwireAuthResponse rokwireAuthResponse = await _getRokwireAccessToken(idToken: newAuthToken?.idToken, saveToken: false);
	// if (rokwireAuthResponse?.token == null) {
	//   // fail
	// }
	// RokwireToken rokwireToken = RokwireToken.fromToken(rokwireAuthResponse?.token);

	// // 3. Request auth user
	// AuthUser newAuthUser = await _loadShibbolethAuthUser(optAuthToken: newAuthToken);
	// if (newAuthUser == null) {
	//   // fail
	// }

	// // 4. Request UserData
	// _loadUserPersonalData(optAuthToken: rokwireToken.accessToken),
	// _loadUserPhotoFromNet(optAuthToken: newAuthToken, optAuthUser: newAuthUser),
}

// Future<AuthToken> _loadShibbolethAuthTokenWithCode(String code, {String idToken}) async {
//     String tokenUriStr;

//     Map<String, dynamic> bodyData = {
//       'code': code,
//       'grant_type': 'authorization_code',
//       'redirect_uri': REDIRECT_URI,
//       'client_id': Config().shibbolethClientId,
//     };

//     if (Config().oidcTokenUrl.contains("{shibboleth_client_id}")) {
//       tokenUriStr = Config()
//           .oidcTokenUrl
//           ?.replaceAll("{shibboleth_client_id}", Config().shibbolethClientId)
//           ?.replaceAll(
//           "{shibboleth_client_secret}", Config().shibbolethClientSecret);
//     } else if (AppString.isStringNotEmpty(Config().shibbolethClientSecret)) {
//       tokenUriStr = Config().oidcTokenUrl;
//       bodyData['client_secret'] = Config().shibbolethClientSecret;
//     } else {
//       tokenUriStr = Config().oidcTokenUrl;
//     }

//     if (_pkceVerifier != null) {
//       bodyData['code_verifier'] = getPKCEVerifier();
//     }

//     // Uri tokenUri = Uri.tryParse(tokenUriStr)?.replace(queryParameters: {
//     //   'scope': "openid profile email offline_access",
//     //   'claims': convert.jsonEncode({
//     //     'id_token': {
//     //       'wiscedu_uhs_id': {'essential': true},
//     //     },
//     //   }),
//     // });
//     // tokenUriStr = tokenUri?.toString();

//     String queryString = Uri(queryParameters: bodyData).query;
//     Map<String, String> headers = {
//       "Content-Type": "application/x-www-form-urlencoded",
//       "Content-Length": convert.utf8.encode(queryString).length.toString()
//     };
//     // if (Config().shibbolethClientSecret != null) {
//     //   headers["Authorization"] = "Basic ${Config().shibbolethClientSecret}";
//     // }

//     Http.Response response;
//     try {
//       response = (tokenUriStr != null) ? await Network().post(tokenUriStr, body: bodyData, headers: headers) : null;
//       String responseBody = (response != null && response.statusCode == 200) ? response.body : null;
//       Map<String,dynamic> jsonData = AppString.isStringNotEmpty(responseBody) ? AppJson.decode(responseBody) : null;
//       if (jsonData != null) {
//         if (idToken != null) {
//           jsonData['id_token'] = idToken;
//         }
//         return ShibbolethToken.fromJson(jsonData);
//       }
//     }
//     catch(e) {
//       print(e?.toString());
//     }
//     return null;
// }

//initOidcAuth initializes and registers a new OIDC auth instance
func initOidcAuth(auth *Auth) (*oidcAuthImpl, error) {
	authInfo := &syncmap.Map{}
	authInfoLock := &sync.RWMutex{}
	oidc := &oidcAuthImpl{auth: auth, authInfo: authInfo, authInfoLock: authInfoLock}

	err := auth.registerAuthType("oidc", oidc)
	if err != nil {
		return nil, err
	}

	err = oidc.loadAuthInfoDocs()
	if err != nil {
		return nil, err
	}

	return oidc, nil
}
