package utils

import (
	"context"
	"net"
	"time"
)

type Runtime struct {
	ReadTimeout    int
	ConnectTimeout int
	Proxy          string
	Host           string
}

func NewRuntime(readTimeout, connectTimeout int, proxy string, host string) *Runtime {
	return &Runtime{
		ReadTimeout:    readTimeout,
		ConnectTimeout: connectTimeout,
		Proxy:          proxy,
		Host:           host,
	}
}

func Timeout(connectTimeout time.Duration) func(cxt context.Context, net, addr string) (c net.Conn, err error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   connectTimeout,
			DualStack: true,
		}).DialContext(ctx, network, address)
	}
}
