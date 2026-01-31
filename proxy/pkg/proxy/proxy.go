package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type Proxy struct {
	httpServer      *http.Server
	httpsServer     *http.Server
	router          atomic.Value
	certs           atomic.Value
	defaultCerts    *tls.Certificate
	autoCertManager *autocert.Manager
}

type ProxyConfig struct {
	Listen           string
	HttpPort         int
	HttpsPort        int
	AutoCertCacheDir string
}

type HostRoute struct {
	Target   *url.URL
	Host     string
	AutoTLS  bool // 自动HTTPS
	AutoCert bool // 自动申请证书
	Proxy    *httputil.ReverseProxy
}

type HostRouter struct {
	level1Routes map[string]*HostRoute // 完全匹配
	level2Routes map[string]*HostRoute // 模糊匹配
}

func (r *HostRouter) Match(req *http.Request) (*HostRoute, bool) {
	host := req.Host
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}
	if p, ok := r.level1Routes[host]; ok {
		return p, true
	}

	index := strings.IndexByte(host, '.')
	host = req.Host[index+1:]
	if p, ok := r.level2Routes[host]; ok {
		return p, true
	}
	return nil, false
}

func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	if cfg.HttpPort <= 0 && cfg.HttpsPort <= 0 {
		return nil, errors.New("http port or https port must be specified")
	}

	var proxy = &Proxy{}
	proxy.router.Store(&HostRouter{
		level1Routes: make(map[string]*HostRoute),
		level2Routes: make(map[string]*HostRoute),
	})
	proxy.certs.Store(make(map[string]*tls.Certificate))

	proxy.autoCertManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			router, ok := proxy.router.Load().(*HostRouter)
			if !ok || router == nil {
				return errors.New("not allowed host")
			}
			if route, ok := router.level1Routes[host]; ok && route.AutoCert {
				return nil
			}
			return errors.New("not allowed host")
		},
		Cache: autocert.DirCache(cfg.AutoCertCacheDir),
	}

	cert, err := GenerateCert("localhost")
	if err != nil {
		return nil, err
	}
	proxy.defaultCerts = &cert

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router, ok := proxy.router.Load().(*HostRouter)
		if !ok || router == nil {
			http.NotFound(w, r)
			return
		}

		p, ok := router.Match(r)
		if !ok {
			http.NotFound(w, r)
			return
		}

		// 自动 TLS 跳转
		if p.AutoTLS && r.TLS == nil {
			// 构造 HTTPS URL
			host := r.Host
			if strings.Contains(host, ":") {
				host, _, _ = net.SplitHostPort(host)
			}
			httpsURL := "https://" + host + ":" + strconv.Itoa(cfg.HttpsPort) + r.URL.RequestURI()
			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			return
		}
		p.Proxy.ServeHTTP(w, r)
	})

	if cfg.HttpPort > 0 {
		proxy.httpServer = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", cfg.Listen, cfg.HttpPort),
			Handler: proxy.autoCertManager.HTTPHandler(handler),
		}
	}

	if cfg.HttpsPort > 0 {
		proxy.httpsServer = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", cfg.Listen, cfg.HttpsPort),
			Handler: handler,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS10,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					certMap := proxy.certs.Load().(map[string]*tls.Certificate)

					if c, ok := certMap[hello.ServerName]; ok {
						return c, nil
					}

					index := strings.IndexByte(hello.ServerName, '.')
					servername := hello.ServerName[index+1:]
					if c, ok := certMap[servername]; ok {
						return c, nil
					}

					// 仅80端口，自动申请证书
					if cfg.HttpPort == 80 {
						if c, err := proxy.autoCertManager.GetCertificate(hello); err == nil && c != nil {
							return c, nil
						}
					}
					return proxy.defaultCerts, nil
				},
			},
		}
	}
	return proxy, nil
}

func (p *Proxy) Start() error {
	// HTTP
	go func() {
		if p.httpServer != nil {
			log.Println("HTTP proxy listening on", p.httpServer.Addr)
			if err := p.httpServer.ListenAndServe(); err != nil {
				log.Println("HTTP server stopped:", err)
			}
		}
	}()
	// HTTPS
	go func() {
		if p.httpsServer != nil {
			log.Println("HTTPS proxy listening on", p.httpsServer.Addr)
			if err := p.httpsServer.ListenAndServeTLS("", ""); err != nil {
				log.Println("HTTPS server stopped:", err)
			}
		}
	}()
	return nil
}

func (p *Proxy) Stop() {
	ctx := context.Background()
	if p.httpServer != nil {
		_ = p.httpServer.Shutdown(ctx)
	}
	if p.httpsServer != nil {
		_ = p.httpsServer.Shutdown(ctx)
	}
}

type LoadRouteConfig struct {
	Host     string
	Target   string
	Rewrite  bool
	Sni      string
	Origin   string
	AutoTLS  bool
	AutoCert bool
}

func (p *Proxy) LoadRoute(routeConfigs []LoadRouteConfig) {
	router := HostRouter{
		level1Routes: make(map[string]*HostRoute),
		level2Routes: make(map[string]*HostRoute),
	}
	for _, r := range routeConfigs {
		target, err := url.Parse(r.Target)
		if err != nil {
			log.Println(r.Host, err)
			continue
		}
		reversProxy, err := newReverseProxy(target, r.Rewrite, r.Sni, r.Origin)
		if err != nil {
			log.Println(r.Host, err)
			continue
		}

		hostRoute := &HostRoute{
			Target:   target,
			Host:     r.Host,
			AutoTLS:  r.AutoTLS,
			AutoCert: r.AutoCert,
			Proxy:    reversProxy,
		}
		if strings.HasPrefix(r.Host, "*.") || strings.HasPrefix(r.Host, ".") {
			index := strings.IndexByte(r.Host, '.')
			router.level2Routes[r.Host[index+1:]] = hostRoute
		} else {
			router.level1Routes[r.Host] = hostRoute
		}
	}
	p.router.Store(&router)
}

type LoadCertConfig struct {
	Host     string
	CertFile string
	KeyFile  string
}

func (p *Proxy) LoadCert(certConfigs []LoadCertConfig) {
	certs := make(map[string]*tls.Certificate)
	for _, c := range certConfigs {
		x509Cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			log.Println(c.Host, err)
			continue
		}
		certs[c.Host] = &x509Cert
	}
	p.certs.Store(certs)
}

func newReverseProxy(u *url.URL, rewrite bool, sni, origin string) (*httputil.ReverseProxy, error) {
	serverName := u.Hostname()
	if sni != "" {
		serverName = sni
	}

	return &httputil.ReverseProxy{
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			r.SetXForwarded()

			// 处理Host请求头
			if rewrite {
				r.Out.Host = r.In.Host
			} else {
				r.Out.Host = u.Host
			}

			o := r.In.Header.Get("Origin")
			if o != "" {
				if origin != "" {
					r.Out.Header.Set("Origin", origin)
				} else {
					r.Out.Header.Set("Origin", o)
				}
			}
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 支持自签名 HTTPS
				//NextProtos:         []string{"h2", "http/1.1"}, // 支持 HTTP/2
				ServerName: serverName,
			},
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          1024,
			MaxIdleConnsPerHost:   128,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		ModifyResponse: func(resp *http.Response) error {
			// 如果是 WebSocket Upgrade，什么都不做
			if resp.StatusCode == http.StatusSwitchingProtocols {
				return nil
			}

			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil
			}

			// 获取客户端原始 Host 和协议
			xForwardedHost := resp.Request.Header.Get("X-Forwarded-Host")
			xForwardProto := resp.Request.Header.Get("X-Forwarded-Proto")

			locURL, err := url.Parse(loc)
			if err != nil {
				return nil
			}

			if locURL.Host == xForwardedHost || locURL.Host == u.Host {
				locURL.Scheme = xForwardProto
				locURL.Host = xForwardedHost
			}

			resp.Header.Set("Location", locURL.String())
			return nil
		},
	}, nil
}

func GenerateCert(host string) (tls.Certificate, error) {
	// 生成 ECDSA P256 私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 证书模板
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	// 自签证书
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 将证书和私钥封装为 tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return tlsCert, nil
}
