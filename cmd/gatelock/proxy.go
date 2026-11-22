package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// settings is settings.json, the app's settings that are no vault's.
type settings struct {
	// Proxy is the proxy Telegram is reached through, "" for none set.
	Proxy string `json:"proxy,omitempty"`
}

func loadSettings(path string) (settings, error) {
	var s settings
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

// save writes the settings to path, all at once, readable by the user
// alone, as a proxy's URL may hold a password.
func (s settings) save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// errBadProxy is what parseProxy fails with. It does not repeat what was
// typed, which may hold a password.
var errBadProxy = errors.New("that is not a proxy: give one like http://127.0.0.1:7890 or socks5://127.0.0.1:7890")

// parseProxy reads a proxy's URL, nil for "". Without a scheme it is an
// HTTP proxy, as in HTTPS_PROXY. Through any of them the Bot API's host
// name is resolved by the proxy, not the Mac.
func parseProxy(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errBadProxy
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, errBadProxy
	}
	u.Path = ""
	return u, nil
}

// proxy is how Telegram is reached: through the proxy set on the Setup
// page, kept in settings.json, else the environment's (HTTPS_PROXY and
// the like, which an app opened from the Finder does not have), else
// directly. A change applies to the next connection.
type proxy struct {
	path string
	url  atomic.Pointer[url.URL] // nil while none is set
	// transport is the bots'.
	transport *http.Transport
}

// newProxy returns the proxy kept at path, if any.
func newProxy(path string) *proxy {
	p := &proxy{path: path, transport: http.DefaultTransport.(*http.Transport).Clone()}
	p.transport.Proxy = func(r *http.Request) (*url.URL, error) {
		if u := p.url.Load(); u != nil {
			return u, nil
		}
		return http.ProxyFromEnvironment(r)
	}
	if s, err := loadSettings(path); err == nil {
		if u, err := parseProxy(s.Proxy); err == nil {
			p.url.Store(u)
		}
	}
	return p
}

// String is the proxy set, "" for none.
func (p *proxy) String() string {
	if u := p.url.Load(); u != nil {
		return u.String()
	}
	return ""
}

// set keeps s as the proxy, none if "", and closes the connections made
// before.
func (p *proxy) set(s string) error {
	u, err := parseProxy(s)
	if err != nil {
		return err
	}
	// What can't be read is written again.
	kept, _ := loadSettings(p.path)
	kept.Proxy = ""
	if u != nil {
		kept.Proxy = u.String()
	}
	if err := kept.save(p.path); err != nil {
		return err
	}
	p.url.Store(u)
	p.transport.CloseIdleConnections()
	return nil
}

// route says how Telegram is reached now: directly, or through which
// proxy, and whether it is the environment's.
func (p *proxy) route() string {
	req, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/", nil)
	u, err := p.transport.Proxy(req)
	switch {
	case err != nil || u == nil:
		return "directly"
	case p.url.Load() == nil:
		return "through " + u.Host + " (from HTTPS_PROXY)"
	}
	return "through " + u.Host
}
