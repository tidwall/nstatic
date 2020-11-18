// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package static

import (
	"bytes"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type site struct {
	mu    sync.RWMutex
	cache map[string]fileInfo
}

// HandlerFunc returns an http.HandlerFunc that does very simple static pages
// serving from the specified path.
// A vars maps can be provided to optionally replace out simple variables in
// the static files. For example, providing variable "MESSAGE"="Hello" will
// turn
//    <html>
//    <body>{{{MESSAGE}}}</body>
//    </html>
// into
//    <html>
//    <body>Hello</body>
//    </html>
func HandlerFunc(path string, vars map[string]string) http.HandlerFunc {
	s := newSite(path)
	return func(w http.ResponseWriter, r *http.Request) {
		code := 0
		var err error
		start := time.Now()
		defer func() {
			elapsed := time.Since(start)
			log.Printf("%s %d %s %s",
				r.Method, code, elapsed, r.URL.Path)
		}()
		var data []byte
		var contentType string
		data, contentType, err = getStaticFile(s, path, r.URL.Path, vars)
		if err != nil {
			if os.IsNotExist(err) {
				code = 404
				http.NotFound(w, r)
			} else {
				code = 500
				log.Printf("error: %s", err)
				http.Error(w, "internal server error", code)
			}
			return
		}
		code = 200
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
	}
}

type fileInfo struct {
	data        []byte
	contentType string
	err         error
}

func bustCache(s *site) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]fileInfo)
}

func newSite(path string) *site {
	s := &site{cache: make(map[string]fileInfo)}
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
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
					bustCache(s)
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
					panic("path not found: '" + path + "'")
				}
				if fi.IsDir() {
					return watcher.Add(path)
				}
				return nil
			})
		if err != nil {
			log.Fatal(err)
		}
		<-done
	}()
	return s
}

func varsReplace(data []byte, vars map[string]string) []byte {
	for name, value := range vars {
		data = bytes.ReplaceAll(data, []byte("{{{"+name+"}}}"), []byte(value))
	}
	return data
}

func getStaticFile(s *site, root, path string, vars map[string]string,
) (data []byte, contentType string, err error) {
	s.mu.RLock()
	info, ok := s.cache[path]
	s.mu.RUnlock()
	if ok {
		return info.data, info.contentType, info.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok = s.cache[path]
	if ok {
		return info.data, info.contentType, info.err
	}
	defer func() {
		s.cache[path] = fileInfo{
			data:        data,
			contentType: contentType,
			err:         err,
		}
	}()
	if strings.HasSuffix(path, ".html") {
		return nil, "", os.ErrNotExist
	}
	if strings.Contains(path, "..") {
		return nil, "", os.ErrNotExist
	}
	if strings.HasSuffix(path, "/") {
		contentType = "text/html"
		data, err = ioutil.ReadFile(root + path + "index.html")
	} else {
		stat, err := os.Stat(root + path)
		if err != nil {
			if os.IsNotExist(err) {
				if strings.HasSuffix(path, "/index") {
					return nil, "", err
				}
				data, err = ioutil.ReadFile(root + path + ".html")
				if err != nil {
					return nil, "", err
				}
			}
		} else if stat.IsDir() {
			contentType = "text/html"
			data, err = ioutil.ReadFile(root + path + "/index.html")
		} else {
			data, err = ioutil.ReadFile(root + path)
		}
	}
	if err != nil {
		return nil, "", err
	}
	if contentType == "" {
		dot := strings.IndexByte(path, '.')
		if dot == -1 {
			contentType = "text/html"
		} else {
			contentType = mime.TypeByExtension(path[dot:])
		}
	}
	if !strings.HasPrefix(contentType, "image/") {
		data = varsReplace(data, vars)
	}
	return data, contentType, nil
}
