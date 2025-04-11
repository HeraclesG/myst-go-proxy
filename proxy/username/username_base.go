package username

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HeraclesG/myst-go-proxy/proxy"
	"github.com/HeraclesG/myst-go-proxy/proxy/zerocopy"
	"github.com/cespare/xxhash/v2"
	"github.com/pariz/gountries"
)

var (
	strUsernameCountryGB = "gb"
	strUsernameCountryUK = "uk"
	strUsernameCountryIT = "it"
	strUsernameCountryDE = "de"
)

var (
	byteUsernameCountry  = []byte("country")
	byteUsernameDuration = []byte("duration")
	byteUsernameSession  = []byte("session")
	byteUsernameIP       = []byte("ip")
	byteUsernameDash     = []byte("-")
	byteUsernameDashDash = []byte("--")
	byteUsernameRandom   = []byte("rr")
)

var (
	hashPool = sync.Pool{}
)

var (
	ErrInvalidParam     = errors.New("invalid param")
	ErrInvalidTargeting = errors.New("invalid targeting")
	ErrInvalidCountry   = errors.New("invalid country")
	ErrInvalidRegion    = errors.New("invalid region")
)

// acquireHash returns a hash from pool
func acquireHash() *xxhash.Digest {
	v := hashPool.Get()
	if v == nil {
		return xxhash.New()
	}
	return v.(*xxhash.Digest)
}

// releaseHash returns hash to pool
func releaseHash(h *xxhash.Digest) {
	h.Reset()
	hashPool.Put(h)
}

type Base struct {
	sessionDuration    time.Duration
	sessionDurationMax time.Duration
	location           *gountries.Query
}

func NewBaseUsername(sessionDuration time.Duration, sessionDurationMax time.Duration, location *gountries.Query) *Base {
	return &Base{location: location, sessionDuration: sessionDuration, sessionDurationMax: sessionDurationMax}
}

func (s *Base) Parse(username []byte, req *proxy.Request) (err error) {
	var sessionID []byte
	params := bytes.Split(username, byteUsernameDashDash)

	if len(params) < 1 {
		return ErrInvalidParam
	}

	for i, p := range params {
		switch i {
		case 0:
			req.ProfileName = p
			continue
		}
		subparams := bytes.Split(p, byteUsernameDash)
		if len(subparams) < 2 {
			return ErrInvalidParam
		}

		if bytes.EqualFold(subparams[0], byteUsernameCountry) {
			if len(subparams[1]) > 2 {
				return ErrInvalidParam
			}

			req.Country = subparams[1]
			continue
		} else if bytes.EqualFold(subparams[0], byteUsernameSession) {
			sessionID = subparams[1]
			continue
		} else if bytes.EqualFold(subparams[0], byteUsernameDuration) {
			duration, err := strconv.Atoi(zerocopy.String(subparams[1]))
			if err != nil {
				return err
			}

			req.SessionDuration = time.Duration(duration) * time.Second
			continue
		} else if bytes.EqualFold(subparams[0], byteUsernameIP) {
			req.IP = subparams[1]
			continue
		}
	}

	if req.Country != nil {
		_, err = s.location.FindCountryByAlpha(zerocopy.String(req.Country))
		if err != nil {
			if strings.EqualFold(zerocopy.String(req.Country), strUsernameCountryUK) { //small hack to accept both US and GB
				req.Country = zerocopy.Bytes(strUsernameCountryGB)
				_, err = s.location.FindCountryByAlpha(zerocopy.String(req.Country))
				if err != nil {
					return ErrInvalidCountry
				}
			} else {
				return err
			}
		}
	}

	if len(sessionID) > 0 {
		if req.SessionDuration <= 0 || req.SessionDuration > s.sessionDurationMax {
			req.SessionDuration = s.sessionDuration
		}

		digest := acquireHash()
		defer releaseHash(digest)

		if req.Country != nil {
			_, err = digest.Write(req.Country)
			if err != nil {
				return err
			}
		}

		_, err = digest.Write(sessionID)
		if err != nil {
			return err
		}

		_, err = digest.WriteString(req.Password)
		if err != nil {
			return err
		}

		req.SessionID = strconv.FormatUint(digest.Sum64(), 10)
	}

	// req.Routes = make([]pkg.Route, 0, 6)

	// if req.Country != nil {
	// 	req.Routes = append(req.Routes, pkg.RouteCountry)
	// }

	// req.Features = make([]pkg.Feature, 0, 2)
	// if req.SessionID != "" {
	// 	req.Features = append(req.Features, pkg.Sticky)
	// } else {
	// 	req.Features = append(req.Features, pkg.Rotating)
	// }

	// if req.SessionDuration > 0 {
	// 	req.Features = append(req.Features, pkg.SessionDuration)
	// }

	req.CreatedAt = time.Now()

	return
}
