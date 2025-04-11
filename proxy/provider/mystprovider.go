package provider

import (
	netproxy "golang.org/x/net/proxy"
)

type MystProvider struct {
	provider string
	dialer   netproxy.Dialer
	country  string
	iptype   string
	status   string
	binded   bool
	bindtype string
}

func NewMystProvider(
	provider string,
	dialer netproxy.Dialer,
	country string,
	iptype string,
	status string,
	binded bool,
	bindtype string,
) *MystProvider {
	return &MystProvider{
		provider: provider,
		dialer:   dialer,
		country:  country,
		iptype:   iptype,
		status:   status,
		binded:   binded,
		bindtype: bindtype,
	}
}

func (s *MystProvider) Name() string {
	return s.provider
}
func (s *MystProvider) Dialer() netproxy.Dialer {
	return s.dialer
}
func (s *MystProvider) Country() string {
	return s.country
}
func (s *MystProvider) Iptype() string {
	return s.iptype
}
func (s *MystProvider) Status() string {
	return s.status
}
func (s *MystProvider) Binded() bool {
	return s.binded
}
func (s *MystProvider) Bindtype() string {
	return s.bindtype
}
func (s *MystProvider) Idle() bool {
	return s.binded == false
}
func (s *MystProvider) SetBinded(binded bool) {
	s.binded = binded
}
