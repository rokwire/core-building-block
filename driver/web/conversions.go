package web

import (
	Def "core-building-block/driver/web/docs/gen"

	"github.com/rokmetro/auth-library/authservice"
)

func pubKeyFromDef(key *Def.PubKey) authservice.PubKey {
	return authservice.PubKey{KeyPem: key.KeyPem, Alg: key.Alg}
}

func pubKeyToDef(key *authservice.PubKey) Def.PubKey {
	return Def.PubKey{KeyPem: key.KeyPem, Alg: key.Alg}
}

func serviceRegFromDef(reg *Def.ServiceReg) authservice.ServiceReg {
	pubKey := pubKeyFromDef(reg.PubKey)
	return authservice.ServiceReg{ServiceID: reg.ServiceId, Host: reg.Host, PubKey: &pubKey}
}

func serviceRegToDef(reg *authservice.ServiceReg) Def.ServiceReg {
	pubKey := pubKeyToDef(reg.PubKey)
	return Def.ServiceReg{ServiceId: reg.ServiceID, Host: reg.Host, PubKey: &pubKey}
}

func serviceRegListToDef(regs []authservice.ServiceReg) []Def.ServiceReg {
	out := make([]Def.ServiceReg, len(regs))
	for i, item := range regs {
		out[i] = serviceRegToDef(&item)
	}
	return out
}
