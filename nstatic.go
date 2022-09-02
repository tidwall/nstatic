// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package nstatic

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	htemplate "html/template"
	ttemplate "text/template"

	"github.com/fsnotify/fsnotify"
	"github.com/klauspost/compress/gzip"
	"github.com/tidwall/tinylru"
)

// A Page is passed to the pageData function
type Page struct {
	Input struct {
		Error       error
		LocalPath   string
		ContentType string
		Request     *http.Request
	}
	Output struct {
		Cookies []*http.Cookie
		Data    interface{}
	}
}

type dataRedirect string

// Redirect will send an HTTP 302 with url as the Location.
func (p *Page) Redirect(url string) {
	p.Output.Data = dataRedirect(url)
}

// SetCookie adds a cookie to the HTTP response
func (p *Page) SetCookie(cookie *http.Cookie) {
	p.Output.Cookies = append(p.Output.Cookies, cookie)
}

type dataOverride struct {
	statusCode  int
	contentType string
	body        []byte
}

// Override the HTTP response with the provide content.
func (p *Page) Override(statusCode int, contentType string, body []byte) {
	p.Output.Data = dataOverride{statusCode, contentType, body}
}

type fileInfo struct {
	localPath           string
	templateName        string
	isTemplate          bool
	isTextTemplate      bool
	isAPIEndpoint       bool
	data                []byte
	contentType         string
	err                 error
	cookies             []*http.Cookie
	redirect            bool
	redirectURL         string
	override            bool
	overrideStatusCode  int
	overrideContentType string
	overrideBody        []byte
}

type site struct {
	mu           sync.RWMutex
	cache        map[string]fileInfo
	funcMap      map[string]interface{}
	apiEndpoints map[string]bool
	gzipCache    tinylru.LRU

	ttmpl *ttemplate.Template
	htmpl *htemplate.Template

	ttmplBuilder *ttemplate.Template
	htmplBuilder *htemplate.Template
}

type FS interface {
	Open(path string) (fs.File, error)
	ReadFile(path string) ([]byte, error)
}

// Options for the handler
type Options struct {
	LogOutput    io.Writer
	PageData     func(page *Page) error
	FuncMap      map[string]interface{}
	AllowGzip    bool
	RedirectHost string
	// APIEndpoints are all the endpoints that are not backed by an html
	// template.
	APIEndpoints []string
	EmbeddedFS   FS
}

type errLogger interface {
	Error(...interface{})
}

func dictFn(vals ...interface{}) (map[string]interface{}, error) {
	if len(vals)%2 != 0 {
		return nil, errors.New("wrong number of dict args")
	}
	dict := make(map[string]interface{}, len(vals)/2)
	for i := 0; i < len(vals); i += 2 {
		key, ok := vals[i].(string)
		if !ok {
			return nil, errors.New("dict keys must be strings")
		}
		dict[key] = vals[i+1]
	}
	return dict, nil
}

// NewHandlerFunc returns an http.HandlerFunc that does very simple pages
// serving from the specified path. The pageData function can be used to return
// template data.
func NewHandlerFunc(path string, opts *Options) (http.HandlerFunc, error) {
	var pageData func(page *Page) error
	var logOutput io.Writer
	var funcMap map[string]interface{}
	var allowGzip bool
	var redirectHost string
	var apiEndpoints []string
	var efs FS
	if opts != nil {
		pageData = opts.PageData
		logOutput = opts.LogOutput
		funcMap = opts.FuncMap
		allowGzip = opts.AllowGzip
		redirectHost = opts.RedirectHost
		apiEndpoints = opts.APIEndpoints
		efs = opts.EmbeddedFS
	}
	if logOutput == nil {
		logOutput = os.Stderr
	}

	if funcMap == nil {
		funcMap = map[string]interface{}{}
	}
	if funcMap["dict"] == nil {
		funcMap["dict"] = dictFn
	}

	if path != "" {
		var err error
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("invalid path: %s: not a directory", path)
		}
		efs = nil
	} else if efs != nil {
		logOutput.Write([]byte("Embedded filesystem"))
	} else {
		return nil, fmt.Errorf("A path or embedded FS is required")
	}

	s := newSite(path, efs, funcMap)
	if len(apiEndpoints) > 0 {
		s.apiEndpoints = make(map[string]bool)
		for _, endpoint := range apiEndpoints {
			s.apiEndpoints[endpoint] = true
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if redirectHost != "" && r.Host != redirectHost {
			var location string
			if r.TLS != nil {
				location = "https://"
			} else {
				location = "http://"
			}
			location += redirectHost + r.URL.String()
			http.Redirect(w, r, location, http.StatusMovedPermanently)
			return
		}
		code := 0
		start := time.Now()
		var perr error
		defer func() {
			elapsed := time.Since(start)
			line := fmt.Sprintf("%d %s %s %s\n",
				code, r.Method, r.URL.Path, formatSmallElapsed(elapsed))
			if code < 400 {
				logOutput.Write([]byte(line))
			} else if log, ok := logOutput.(errLogger); ok {
				log.Error(line)
			} else {
				logOutput.Write([]byte(line))
			}
			if perr != nil {
				if log, ok := logOutput.(errLogger); ok {
					log.Error(perr.Error())
				} else {
					fmt.Fprintf(logOutput, "%s\n", perr)
				}
			}
		}()
		info := getStaticFile(s, path, r.URL.Path, efs, r, pageData,
			true, false, nil, allowGzip)
		if info.err != nil {
			if os.IsNotExist(info.err) {
				code = 404
				info = getStaticFile(s, path, "/_404", efs, r, pageData,
					true, true, nil, allowGzip)
				if info.err != nil {
					info = getStaticFile(s, path, "/~404", efs, r, pageData,
						true, true, nil, allowGzip)
					if info.err != nil {
						http.NotFound(w, r)
						return
					}
				}
			} else {
				code = 500
				perr = info.err
				info = getStaticFile(s, path, "/_500", efs, r, pageData,
					true, true, info.err, allowGzip)
				if info.err != nil {
					info = getStaticFile(s, path, "/~500", efs, r, pageData,
						true, true, info.err, allowGzip)
					if info.err != nil {
						http.Error(w, "500 Internal Server Error", code)
						return
					}
				}
			}
		} else {
			code = 200
			for _, cookie := range info.cookies {
				http.SetCookie(w, cookie)
			}
			if info.redirect {
				code = 302
				w.Header().Set("Location", info.redirectURL)
				w.WriteHeader(code)
				return
			}
			if info.override {
				info.contentType = info.overrideContentType
				info.data = info.overrideBody
				code = info.overrideStatusCode
			}
		}

		w.Header().Set("Content-Type", info.contentType)
		data := info.data
		if code != 200 {
			// write the error asap
			w.WriteHeader(code)
			w.Write(data)
			return
		}

		w.Header().Set("Accept-Ranges", "none")
		var etag string
		if allowGzip &&
			strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") &&
			shouldGzipMimeType(info.contentType) {
			w.Header().Set("Content-Encoding", "gzip")
			sum := sha1.Sum(data)
			key := fmt.Sprintf("%s:%d", sum[:], len(data))
			value, ok := s.gzipCache.Get(key)
			if ok {
				data = value.([]byte)
			} else {
				var buf bytes.Buffer
				zw := gzip.NewWriter(&buf)
				zw.Write(data)
				zw.Close()
				data = buf.Bytes()
				s.gzipCache.Set(key, data)
			}
		}
		etag = makeEtag(data)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		if r.Header.Get("If-None-Match") == etag {
			code = 304
			w.WriteHeader(code)
		} else {
			w.Header().Set("ETag", etag)
			w.WriteHeader(code)
			w.Write(data)
		}
	}, nil
}

func shouldGzipMimeType(mtype string) bool {
	switch {
	case strings.HasPrefix(mtype, "image/"):
		return false
	case strings.HasPrefix(mtype, "font/"):
		return false
	case strings.HasPrefix(mtype, "video/"):
		return false
	}
	return true
}

func makeEtag(body []byte) string {
	sum := sha1.Sum(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func formatSmallElapsed(elapsed time.Duration) string {
	if elapsed < time.Microsecond {
		return fmt.Sprintf("%dns", elapsed)
	}
	if elapsed < time.Millisecond {
		return fmt.Sprintf("%dµs", elapsed/time.Microsecond)
	}
	if elapsed < time.Second {
		return fmt.Sprintf("%dms", elapsed/time.Millisecond)
	}
	return fmt.Sprintf("%ds", elapsed/time.Second)
}

func (s *site) bustCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]fileInfo)
	s.gzipCache = tinylru.LRU{}
	s.gzipCache.Resize(5000)
	s.htmplBuilder = htemplate.New("")
	s.ttmplBuilder = ttemplate.New("")
	s.htmpl = htemplate.New("")
	s.ttmpl = ttemplate.New("")

}

func newSite(path string, efs FS, funcMap map[string]interface{}) *site {
	s := &site{}
	s.bustCache()
	s.funcMap = funcMap
	if efs != nil {
		return s
	}
	go func() {
		for {
			func() {
				watcher, err := fsnotify.NewWatcher()
				if err != nil {
					panic(err)
				}
				defer watcher.Close()
				done := make(chan bool)
				go func() {
					for {
						select {
						case _, ok := <-watcher.Events:
							if !ok {
								return
							}
							s.bustCache()
						case _, ok := <-watcher.Errors:
							if !ok {
								return
							}
						}
					}
				}()
				err = filepath.Walk(path,
					func(path string, fi os.FileInfo, err error) error {
						if fi == nil {
							return errors.New("path not found: '" + path + "'")
						}
						if fi.IsDir() {
							return watcher.Add(path)
						}
						return nil
					})
				if err != nil {
					return
				}
				<-done
			}()
			time.Sleep(time.Second)
		}
	}()
	return s
}

func getStaticFile(s *site, root, path string, efs FS, r *http.Request,
	pageData func(page *Page) error,
	execTemplate, allowUnderscore bool, externalError error,
	allowGzip bool,
) (info fileInfo) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	apiEndpoint := s.apiEndpoints[path]
	defer func() {
		if !allowUnderscore && info.err == nil &&
			(strings.HasPrefix(filepath.Base(info.localPath), "_") ||
				strings.HasPrefix(filepath.Base(info.localPath), "~")) {
			info = fileInfo{err: os.ErrNotExist}
			return
		}
		if info.err == nil && pageData != nil &&
			(info.isTemplate || info.isAPIEndpoint) {
			var pdata interface{}
			var err error
			if execTemplate {
				page := new(Page)
				page.Input.LocalPath = info.localPath
				page.Input.ContentType = info.contentType
				page.Input.Request = r
				page.Input.Error = externalError
				func() {
					s.mu.RUnlock()
					defer s.mu.RLock()
					err = pageData(page)
				}()
				pdata = page.Output.Data
				info.cookies = page.Output.Cookies
				switch v := page.Output.Data.(type) {
				case dataRedirect:
					info.redirect = true
					info.redirectURL = string(v)
				case dataOverride:
					info.override = true
					info.overrideStatusCode = v.statusCode
					info.overrideContentType = v.contentType
					info.overrideBody = v.body
				}
			}
			if err != nil {
				info.err = err
				return
			}
		again:
			if !execTemplate || info.redirect || info.override || apiEndpoint {
				return
			}
			var out bytes.Buffer
			name := info.templateName
			if !info.isTextTemplate {
				info.err = s.htmpl.ExecuteTemplate(&out, name, pdata)
			} else {
				info.err = s.ttmpl.ExecuteTemplate(&out, name, pdata)
			}
			if info.err != nil {
				errmsg := info.err.Error()
				tag := `no such template "`
				if strings.Contains(errmsg, tag) {
					name := strings.Split(strings.Split(errmsg, tag)[1], `"`)[0]
					func() {
						s.mu.RUnlock()
						defer s.mu.RLock()
						sinfo := getStaticFile(s, root, "/"+name, efs, r,
							pageData, false, true, nil, allowGzip)
						if sinfo.err == nil {
							info.err = nil
						} else if !os.IsNotExist(sinfo.err) {
							info.err = sinfo.err
						}
					}()
					if info.err == nil {
						goto again
					}
				}
				return
			}
			info.data = out.Bytes()
		}
	}()
	if apiEndpoint {
		info.isAPIEndpoint = true
		return info
	}

	var ok bool
	info, ok = s.cache[path]
	if ok {
		return info
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		s.mu.RLock()
	}()
	info, ok = s.cache[path]
	if ok {
		return info
	}
	defer func() { s.cache[path] = info }()

	var localPath string
	readFile := func(path string) ([]byte, error) {
		localPath = path[len(root)+1:]
		if efs != nil {
			// path = path[1:]
			return efs.ReadFile(path)
		}
		return ioutil.ReadFile(path)
	}

	var data []byte
	var err error
	if !execTemplate {
		data, err = readFile(root + path)
	} else {
		if strings.HasSuffix(path, ".html") {
			return fileInfo{err: os.ErrNotExist}
		}
		if strings.Contains(path, "..") {
			return fileInfo{err: os.ErrNotExist}
		}
		if strings.HasSuffix(path, "/") {
			data, err = readFile(root + path + "index.html")
		} else {
			var isdir bool
			isdir, err = isDir(root+path, efs)
			if err != nil {
				if os.IsNotExist(err) {
					if strings.HasSuffix(path, "/index") {
						return fileInfo{err: err}
					}
					data, err = readFile(root + path + ".html")
				}
				if os.IsNotExist(err) {
					tpath := "/" + strings.Replace(path, "/", "$", -1)[1:]
					data, err = readFile(root + tpath + ".html")
				}
			} else if isdir {
				data, err = readFile(root + path + "/index.html")
			} else {
				data, err = readFile(root + path)
			}
		}
	}
	if err != nil {
		return fileInfo{err: err}
	}
	info = fileInfo{
		localPath:   localPath,
		data:        data,
		contentType: mime.TypeByExtension(filepath.Ext(localPath)),
	}
	if pageData != nil {
		mimeType := info.plainContenType()
		switch {
		case mimeType == "text/html":
			// html template
			info.templateName = info.localPath
			info.isTemplate = true
			info.isTextTemplate = false
			_, err = s.htmplBuilder.New(info.templateName).
				Funcs(s.funcMap).Parse(string(info.data))
			if err == nil {
				var htmpl *htemplate.Template
				htmpl, err = s.htmplBuilder.Clone()
				if err == nil {
					s.htmpl = htmpl
				}
			}
		case mimeType == "application/javascript" ||
			strings.HasPrefix(mimeType, "text/"):
			// text template
			info.templateName = info.localPath
			info.isTemplate = true
			info.isTextTemplate = true
			_, err = s.ttmplBuilder.New(info.templateName).
				Funcs(s.funcMap).Parse(string(info.data))
			if err == nil {
				var ttmpl *ttemplate.Template
				ttmpl, err = s.ttmplBuilder.Clone()
				if err == nil {
					s.ttmpl = ttmpl
				}
			}
		}
		if err != nil {
			return fileInfo{err: err}
		}
	}
	return info
}

func isDir(path string, efs FS) (bool, error) {
	var stat fs.FileInfo
	var err error
	if efs != nil {
		var f fs.File
		f, err = efs.Open(path)
		if err != nil {
			return false, err
		}
		defer f.Close()
		stat, err = f.Stat()
	} else {
		stat, err = os.Stat(path)
	}
	if err != nil {
		return false, err
	}
	return stat.IsDir(), nil
}

func (info fileInfo) plainContenType() string {
	scol := strings.IndexByte(info.contentType, ';')
	if scol == -1 {
		return info.contentType
	}
	return info.contentType[:scol]
}
