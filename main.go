// Command pagetest fetches provided url and all linked resources, printing
// diagnostic timings.
//
// pagetest first fetches html page at given url, then parses html, extracting
// absolute urls from <link>, <script>, <img> tag attributes, then issues HEAD
// requests to these urls and reports timings and response codes for all
// requests done.
//
// On certain requests for the same domain some of the reported timings may be
// zero, this is a result of connection reuse.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/net/html/charset"
)

func main() {
	args := runArgs{}
	flag.StringVar(&args.URL, "url", args.URL, "url to check")
	flag.Parse()
	if err := run(args); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

type runArgs struct {
	URL string
}

func run(args runArgs) error {
	twr := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
	defer twr.Flush()
	if args.URL == "" {
		return fmt.Errorf("empty url")
	}
	ts, resp, err := doRequest(context.Background(), http.MethodGet, args.URL)
	if err != nil {
		return err
	}
	fmt.Fprintln(twr, "url\tcode\tDNS lookup\tTCP connect\tTLS handshake\tfirst byte\t")
	var mu sync.Mutex // guards twr writes
	report := func(s string, code int, ts *timings) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(twr, "%s\t%d\t%v\t%v\t%v\t%v\t\n",
			s, code, ts.Lookup.Round(time.Millisecond),
			ts.Connect.Round(time.Millisecond),
			ts.Handshake.Round(time.Millisecond),
			ts.FirstByte.Round(time.Millisecond))
	}
	report(args.URL, resp.StatusCode, ts)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %q", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		return fmt.Errorf("unsupported Content-Type: %q", ct)
	}
	rd, err := charset.NewReader(resp.Body, ct)
	if err != nil {
		return fmt.Errorf("charset detect: %w", err)
	}
	cand, err := extractLinks(rd)
	if err != nil {
		return err
	}
	orig := &url.URL{
		Scheme: resp.Request.URL.Scheme,
		Host:   resp.Request.URL.Host,
		Path:   resp.Request.URL.Path,
	}
	links := cand[:0]
	for _, s := range cand {
		if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
			continue
		}
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		if u.Scheme == orig.Scheme && u.Host == orig.Host && u.Path == orig.Path {
			continue
		}
		links = append(links, s)
	}
	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range ch {
				ts, err := func(s string) (*timings, error) {
					ts, resp, err := doRequest(context.Background(), http.MethodHead, s)
					if err != nil {
						return nil, err
					}
					resp.Body.Close()
					return ts, nil
				}(s)
				switch err {
				case nil:
					report(s, resp.StatusCode, ts)
				default:
					fmt.Fprintf(os.Stderr, "%s\t%v\n", s, err)
				}
			}
		}()
	}
	for _, s := range links {
		ch <- s
	}
	close(ch)
	wg.Wait()
	return nil
}

func doRequest(ctx context.Context, method, url string) (*timings, *http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, nil, err
	}
	// logic inspired by github.com/davecheney/httpstat
	var dnsStart, dnsDone, connStart, connDone, gotConn, firstByte, tlsStart, tlsDone time.Time
	trace := &httptrace.ClientTrace{
		DNSStart:             func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart:         func(_, _ string) { connStart = time.Now() },
		ConnectDone:          func(_, _ string, _ error) { connDone = time.Now() },
		GotConn:              func(_ httptrace.GotConnInfo) { gotConn = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	ts := &timings{
		Lookup:    dnsDone.Sub(dnsStart),
		Connect:   connDone.Sub(connStart),
		Handshake: tlsDone.Sub(tlsStart),
		FirstByte: firstByte.Sub(gotConn),
	}
	if !tlsDone.IsZero() {
		ts.FirstByte = firstByte.Sub(tlsDone)
	}
	return ts, resp, nil
}

type timings struct {
	Lookup    time.Duration
	Connect   time.Duration
	Handshake time.Duration
	FirstByte time.Duration
}

func extractLinks(r io.Reader) ([]string, error) {
	z := html.NewTokenizer(r)
	var cand []string
	for {
		tt := z.Next()
		switch tt {
		default:
			continue
		case html.ErrorToken:
			if z.Err() == io.EOF {
				return cand, nil
			}
			return nil, z.Err()
		case html.StartTagToken, html.SelfClosingTagToken:
		}
		name, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		var k, v []byte
		switch atom.Lookup(name) {
		case atom.Link:
			for hasAttr {
				if k, v, hasAttr = z.TagAttr(); string(k) == "href" {
					cand = append(cand, string(v))
				}
			}
		case atom.Script, atom.Img:
			for hasAttr {
				if k, v, hasAttr = z.TagAttr(); string(k) == "src" {
					cand = append(cand, string(v))
				}
			}
		}
	}
}

//go:generate usagegen -autohelp
//go:generate sh -c "go doc > README"