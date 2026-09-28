package dns

import (
	"context"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
)

// IPOption is an object for IP query options.
type IPOption struct {
	IPv4Enable bool
	IPv6Enable bool
	FakeEnable bool
}

// Client is a Xray feature for querying DNS information.
//
// xray:api:stable
type Client interface {
	features.Feature

	// LookupIP returns IP address for the given domain. IPs may contain IPv4 and/or IPv6 addresses.
	LookupIP(domain string, option IPOption) ([]net.IP, uint32, error)
}

// ContextClient is an optional cancellation capability. Client remains source compatible.
type ContextClient interface {
	LookupIPContext(context.Context, string, IPOption) ([]net.IP, uint32, error)
}

// LookupIPContext uses the contextual capability when available. Legacy clients run
// synchronously: their in-flight work cannot be canceled by this adapter.
func LookupIPContext(ctx context.Context, c Client, domain string, option IPOption) ([]net.IP, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if c, ok := c.(ContextClient); ok {
		return c.LookupIPContext(ctx, domain, option)
	}
	ips, ttl, err := c.LookupIP(domain, option)
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	return ips, ttl, err
}

// ClientType returns the type of Client interface. Can be used for implementing common.HasType.
//
// xray:api:beta
func ClientType() interface{} {
	return (*Client)(nil)
}

// ErrEmptyResponse indicates that DNS query succeeded but no answer was returned.
var ErrEmptyResponse = errors.New("empty response")

const DefaultTTL = 300

type RCodeError uint16

func (e RCodeError) Error() string {
	return serial.Concat("rcode: ", uint16(e))
}

func (RCodeError) IP() net.IP {
	panic("Calling IP() on a RCodeError.")
}

func (RCodeError) Domain() string {
	panic("Calling Domain() on a RCodeError.")
}

func (RCodeError) Family() net.AddressFamily {
	panic("Calling Family() on a RCodeError.")
}

func (e RCodeError) String() string {
	return e.Error()
}

var _ net.Address = (*RCodeError)(nil)

func RCodeFromError(err error) uint16 {
	if err == nil {
		return 0
	}
	cause := errors.Cause(err)
	if r, ok := cause.(RCodeError); ok {
		return uint16(r)
	}
	return 0
}
