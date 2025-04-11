package proxy

import (
	"errors"
)

var (
	ErrNotEnoughData      = errors.New("not enough data")
	ErrMissingAuth        = errors.New("missing auth")
	ErrPurchaseNotFound   = errors.New("purchase not found")
	ErrDomainBlocked      = errors.New("domain blocked")
	ErrIPNotAllowed       = errors.New("ip not allowed")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type Auth interface {
	Authenticate(username string, password string) error
}
