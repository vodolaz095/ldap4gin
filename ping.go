package ldap4gin

import (
	"context"

	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func (a *Authenticator) redial(initialCtx context.Context) (err error) {
	ctx, span := otel.Tracer("github.com/vodolaz095/ldap4gin").Start(initialCtx, "ldap4gin.redial",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	a.LDAPConn, err = ldap.DialURL(a.Options.ConnectionString, ldap.DialWithTLSConfig(a.Options.TLS))
	if err != nil {
		a.debug(ctx, "error dialing ldap via %s: %s", a.Options.ConnectionString, err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if a.Options.StartTLS {
		span.AddEvent("starting tls...")
		err = a.LDAPConn.StartTLS(a.Options.TLS)
		if err != nil {
			a.debug(ctx, "error starting tls via %s: %s", a.Options.ConnectionString, err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
	}
	a.debug(ctx, "ldap connection restored")
	span.AddEvent("ldap connection is restored")
	return nil
}

// Ping ensures connection to ldap server is responding
func (a *Authenticator) Ping(initialCtx context.Context) (err error) {
	ctx, span := otel.Tracer("github.com/vodolaz095/ldap4gin").Start(initialCtx, "ldap4gin.ping",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	if a.LDAPConn == nil {
		a.debug(ctx, "connection is not initialized")
		span.AddEvent("connection is not initialized")
		err = a.redial(ctx)
		if err != nil {
			return err
		}
	} else {
		a.debug(ctx, "ldap connection is active")
		span.AddEvent("ldap connection is active")
	}
	result, err := a.LDAPConn.WhoAmI(nil)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
			err = a.redial(ctx)
			if err != nil {
				return err
			}
			return nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	span.AddEvent("whoami is " + result.AuthzID)
	return nil
}
