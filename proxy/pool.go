package proxy

import (
	"sync"
)

var (
	requestPool sync.Pool
)

func acquireRequest() *Request {
	v := requestPool.Get()
	if v == nil {
		return &Request{}
	}
	return v.(*Request)
}

func releaseRequest(req *Request) {
	if req.Provider != nil && req.SessionID == "" {
		req.Provider.SetBinded(false)
	}
	req.reset()
	requestPool.Put(req)
}
