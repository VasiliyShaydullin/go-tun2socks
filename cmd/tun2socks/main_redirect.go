//go:build redirect
// +build redirect

package main

import (
	"github.com/vasiliyshaydullin/go-tun2socks/core"
	"github.com/vasiliyshaydullin/go-tun2socks/proxy/redirect"
)

func init() {
	args.addFlag(fProxyServer)
	args.addFlag(fUdpTimeout)

	registerHandlerCreater("redirect", func() {
		core.RegisterTCPConnHandler(redirect.NewTCPHandler(*args.ProxyServer))
		core.RegisterUDPConnHandler(redirect.NewUDPHandler(*args.ProxyServer, *args.UdpTimeout))
	})
}
