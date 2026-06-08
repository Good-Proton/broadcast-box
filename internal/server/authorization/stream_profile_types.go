package authorization

import (
	"strings"
)

// Internal profile struct, do not use for endpoints
type profile struct {
	FileName string
	IsActive bool
	IsPublic bool
	MOTD     string
}

var separator = "_"

func (p *profile) streamKey() string {
	splitIndex := strings.LastIndex(p.FileName, separator)
	return p.FileName[:splitIndex+len(separator)-1]
}
func (p *profile) streamToken() string {
	splitIndex := strings.LastIndex(p.FileName, separator)
	return p.FileName[splitIndex+len(separator):]
}
func (p *profile) asPublicProfile() *PublicProfile {
	return &PublicProfile{
		StreamKey: p.streamKey(),
		IsActive:  p.IsActive,
		IsPublic:  p.IsPublic,
		MOTD:      p.MOTD,
	}
}
func (p *profile) asPersonalProfile() *PersonalProfile {
	return &PersonalProfile{
		StreamKey: p.streamKey(),
		IsActive:  p.IsActive,
		IsPublic:  p.IsPublic,
		MOTD:      p.MOTD,
	}
}
func (p *profile) asAdminProfile() *adminProfile {
	return &adminProfile{
		StreamKey: p.streamKey(),
		Token:     p.streamToken(),
		IsPublic:  p.IsPublic,
		MOTD:      p.MOTD,
	}
}

// Public profile struct for serving to public endpoints
type PublicProfile struct {
	StreamKey string `json:"streamKey"`
	LhUserId  string `json:"lhUserId,omitempty"`
	IsActive  bool   `json:"isActive"`
	IsPublic  bool   `json:"isPublic"`
	MOTD      string `json:"motd"`
}

// Personal profile struct for serving to profile owner endpoints
type PersonalProfile struct {
	StreamKey string `json:"streamKey"`
	IsActive  bool   `json:"isActive"`
	IsPublic  bool   `json:"isPublic"`
	MOTD      string `json:"motd"`
}

// Admin profile struct for serving to admin specific endpoints
type adminProfile struct {
	StreamKey string `json:"streamKey"`
	Token     string `json:"token"`
	IsPublic  bool   `json:"isPublic"`
	MOTD      string `json:"motd"`
}
