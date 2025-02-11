package ldap4gin

import (
	"context"

	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Ping ensures connection to ldap server is responding
func (a *Authenticator) Ping(ctx context.Context) (err error) {
	_, span := otel.Tracer("github.com/vodolaz095/ldap4gin").Start(ctx, "ldap4gin.ping",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	span.AddEvent("binding as readonly")
	span.SetAttributes(attribute.String("bind.readonly_dn", a.Options.ReadonlyDN))
	err = a.LDAPConn.Bind(a.Options.ReadonlyDN, a.Options.ReadonlyPasswd)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			span.AddEvent("invalid credentials for readonly user")
			err = ErrReadonlyWrongCredentials
			return
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	result, err := a.LDAPConn.WhoAmI(nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.AddEvent(result.AuthzID)
	return err
}
