package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//AnonymousProfile
func anonymousProfileFromDef(item *Def.AnonymousProfile) model.AnonymousProfile {
	if item == nil {
		return model.AnonymousProfile{}
	}
	return model.AnonymousProfile{ID: item.Id, Interests: defStringArray(item.Interests), Favorites: defStringArray(item.Favorites), PositiveInterestTags: defStringArray(item.PositiveInterestTags), NegativeInterestTags: defStringArray(item.NegativeInterestTags), PrivacySettings: defString(item.PrivacySettings), CreationDate: defTimestamp(item.CreationDate), LastModifiedDate: defTimestamp(item.LastModifiedDate), Over13: defBool(item.Over13)}
}

func anonymousProfileToDef(item *model.AnonymousProfile) *Def.AnonymousProfile {
	if item == nil {
		return nil
	}

	creationDate := item.CreationDate.String()
	lastModifiedDate := item.LastModifiedDate.String()
	var over13 string
	if item.Over13 {
		over13 = "true"
	} else {
		over13 = "false"
	}

	//TODO: handle permissions
	return &Def.AnonymousProfile{Id: item.ID, Interests: &item.Interests, Favorites: &item.Favorites, PositiveInterestTags: &item.PositiveInterestTags, NegativeInterestTags: &item.NegativeInterestTags, PrivacySettings: &item.PrivacySettings, CreationDate: &creationDate, LastModifiedDate: &lastModifiedDate, Over13: &over13}
}
