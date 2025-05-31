package ldap4gin

import (
	"context"

	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Ping ensures connection to ldap server is responding
func (a *Authenticator) Ping(initialCtx context.Context) (err error) {
	_, span := otel.Tracer("github.com/vodolaz095/ldap4gin").Start(initialCtx, "ldap4gin.ping",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	if a.LDAPConn == nil {
		span.AddEvent("connection is not initialized")
		a.LDAPConn, err = ldap.DialURL(a.Options.ConnectionString, ldap.DialWithTLSConfig(a.Options.TLS))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		if a.Options.StartTLS {
			span.AddEvent("starting tls...")
			err = a.LDAPConn.StartTLS(a.Options.TLS)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return err
			}
		}
		span.AddEvent("ldap connection is restored")
	} else {
		span.AddEvent("ldap connection is active")
	}
	result, err := a.LDAPConn.WhoAmI(nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	span.AddEvent("whoami is " + result.AuthzID)
	return nil
}
