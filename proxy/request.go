package proxy

import (
	"sync/atomic"
	"time"
)

type Request struct {
	ID     string
	UserIP string
	Host   string
	Target string

	//Targeting
	IP      []byte
	Country []byte

	ProfileName []byte
	Category    []byte
	Product     []byte
	PurchaseID  uint

	SessionID       string
	SessionDuration time.Duration

	Password string

	Written int64

	CreatedAt time.Time
	Provider  Provider

	Done chan struct{}
}

func (r *Request) reset() {
	close(r.Done)

	r.ID = ""
	r.UserIP = ""
	r.Host = ""
	r.Target = ""
	r.Country = nil
	r.IP = nil
	r.SessionID = ""
	r.SessionDuration = 0
	r.Password = ""
	atomic.StoreInt64(&r.Written, 0)
	r.CreatedAt = time.Time{}
	r.Done = make(chan struct{}, 1)
	r.Provider = nil
}

func (r *Request) Inc(written int64) int64 {
	return atomic.AddInt64(&r.Written, written)
}

func RequestKey(apiKey string, ID string) string {
	return apiKey + ":" + ID
}
