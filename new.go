package ldap4gin

import (
	"context"
	"sync"
)

// New creates new authenticator using options provided
func New(opts *Options) (a *Authenticator, err error) {
	a = &Authenticator{
		mu:      &sync.Mutex{},
		Options: opts,
	}
	a.fields = GetDefaultFields()
	a.fields = append(a.fields, opts.ExtraFields...)
	if opts.LogDebugFunc != nil {
		a.LogDebugFunc = opts.LogDebugFunc
	} else {
		a.LogDebugFunc = DefaultLogDebugFunc
	}
	err = a.checkConnection(context.Background())
	if err != nil {
		return nil, err
	}
	return a, nil
}
