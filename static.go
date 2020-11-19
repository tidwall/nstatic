// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package static

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
)

// A Page is passed to the pageData function
type Page struct {
	LocalPath   string
	ContentType string
	Request     *http.Request
	Error       error
}

type fileInfo struct {
	localPath      string
	templateName   string
	isTemplate     bool
	isTextTemplate bool
	data           []byte
	contentType    string
	err            error
}

type site struct {
	mu    sync.RWMutex
	cache map[string]fileInfo

	ttmpl *ttemplate.Template
	htmpl *htemplate.Template

	ttmplBuilder *ttemplate.Template
	htmplBuilder *htemplate.Template
}

// Options for the handler
type Options struct {
	LogOutput io.Writer
	PageData  func(page Page) (interface{}, error)
}

type errLogger interface {
	Error(...interface{})
}

// NewHandlerFunc returns an http.HandlerFunc that does very simple pages
// serving from the specified path. The pageData function can be used to return
// template data.
func NewHandlerFunc(path string, opts *Options) (http.HandlerFunc, error) {
	var pageData func(page Page) (interface{}, error)
	var logOutput io.Writer
	if opts != nil {
		pageData = opts.PageData
		logOutput = opts.LogOutput
	}
	if logOutput == nil {
		logOutput = os.Stderr
	}

	path, err := filepath.Abs(path)
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

	s := newSite(path)

	return func(w http.ResponseWriter, r *http.Request) {
		code := 0
		start := time.Now()
		var perr error
		defer func() {
			elapsed := time.Since(start)
			line := fmt.Sprintf("%d %s %s %s\n",
				code, r.Method, r.URL.Path, formatSmallElapsed(elapsed))
			if code == 200 {
				logOutput.Write([]byte(line))
			} else if log, ok := logOutput.(errLogger); ok {
				log.Error(line)
			} else {
				logOutput.Write([]byte(line))
			}
			_ = perr
		}()

		info := getStaticFile(s, path, r.URL.Path, r, pageData,
			true, false, nil)
		if info.err != nil {
			if os.IsNotExist(info.err) {
				code = 404
				info = getStaticFile(s, path, "/_404", r, pageData,
					true, true, nil)
				if info.err != nil {
					http.NotFound(w, r)
					return
				}
			} else {
				code = 500
				perr = info.err
				info = getStaticFile(s, path, "/_500", r, pageData,
					true, true, info.err)
				if info.err != nil {
					http.Error(w, "500 internal server error", code)
					return
				}
			}
		} else {
			code = 200
		}
		w.Header().Set("Content-Type", info.contentType)
		w.Write(info.data)
	}, nil
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
	s.htmplBuilder = htemplate.New("")
	s.ttmplBuilder = ttemplate.New("")
	s.htmpl = htemplate.New("")
	s.ttmpl = ttemplate.New("")
}

func newSite(path string) *site {
	s := &site{}
	s.bustCache()
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

func getStaticFile(s *site, root, path string, r *http.Request,
	pageData func(page Page) (interface{}, error),
	execTemplate, allowUnderscore bool, externalError error,
) (info fileInfo) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	defer func() {
		if !allowUnderscore && info.err == nil &&
			strings.HasPrefix(filepath.Base(info.localPath), "_") {
			info = fileInfo{err: os.ErrNotExist}
			return
		}
		if info.err == nil && pageData != nil && info.isTemplate {
			pdata, err := pageData(Page{
				LocalPath:   info.localPath,
				ContentType: info.contentType,
				Request:     r,
				Error:       externalError,
			})
			if err != nil {
				info.err = err
				return
			}
		again:
			if !execTemplate {
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
						sinfo := getStaticFile(s, root, "/"+name, r,
							pageData, false, true, nil)
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
			stat, err := os.Stat(root + path)
			if err != nil {
				if os.IsNotExist(err) {
					if strings.HasSuffix(path, "/index") {
						return fileInfo{err: err}
					}
					data, err = readFile(root + path + ".html")
					if err != nil {
						return fileInfo{err: err}
					}
				}
			} else if stat.IsDir() {
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
		if strings.HasPrefix(info.plainContenType(), "text/") {
			info.templateName = info.localPath
			info.isTemplate = true
			name := info.templateName
			if info.plainContenType() == "text/html" {
				_, err = s.htmplBuilder.New(name).Parse(string(info.data))
				info.isTextTemplate = false
				if err == nil {
					var htmpl *htemplate.Template
					htmpl, err = s.htmplBuilder.Clone()
					if err == nil {
						s.htmpl = htmpl
					}
				}
			} else {
				_, err = s.ttmplBuilder.New(name).Parse(string(info.data))
				info.isTextTemplate = true
				if err == nil {
					var ttmpl *ttemplate.Template
					ttmpl, err = s.ttmplBuilder.Clone()
					if err == nil {
						s.ttmpl = ttmpl
					}
				}
			}
		}
		if err != nil {
			return fileInfo{err: err}
		}
	}
	return info
}

func (info fileInfo) plainContenType() string {
	scol := strings.IndexByte(info.contentType, ';')
	if scol == -1 {
		return info.contentType
	}
	return info.contentType[:scol]
}
