package proxy

import (
	netproxy "golang.org/x/net/proxy"
)

const (
	ProviderStatic      = "static"
	ProviderDataImpulse = "dataimpulse"
	ProviderTTProxy     = "ttproxy"
	ProviderProxyverse  = "proxyverse"
	ProviderDatabay     = "databay"
)

type Feature []byte

var (
	Rotating        Feature = []byte("rotating")
	Sticky          Feature = []byte("sticky")
	SessionDuration Feature = []byte("duration")
)

type Route string

const (
	RouteContinent Route = "continent"
	RouteCountry   Route = "country"
	RouteRegion    Route = "region"
	RouteCity      Route = "city"
)

type Provider interface {
	Name() string

	//Weight - weight used in provider selection
	Dialer() netproxy.Dialer
	Country() string
	Iptype() string
	Status() string
	Binded() bool
	Bindtype() string
	Idle() bool
	SetBinded(binded bool)
}
