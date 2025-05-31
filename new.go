package ldap4gin

import (
	"context"
	"sync"
	"time"
)

// New creates new authenticator using options provided
func New(opts *Options) (a *Authenticator, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
	err = a.Ping(ctx)
	if err != nil {
		return nil, err
	}
	err = a.LDAPConn.Bind(a.Options.ReadonlyDN, a.Options.ReadonlyPasswd)
	if err != nil {
		return nil, err
	}
	a.debug(ctx, "Bound as %s", a.Options.ReadonlyDN)
	return a, nil
}
