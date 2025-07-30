# Nstatic documentation

## Getting started

The most basic website:

** main.go **

```go
package main

import (
    "net/http"
    "log"

    "github.com/tidwall/nstatic"
)

func main() {
    handler, err := nstatic.NewHandlerFunc("website_root", nil)
    if err != nil {
        log.Fatal(err)
    }
    http.HandleFunc("/", handler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

** website_root/index.html **

```html
<html>
<head>
<title>Homepage</title>
</head>
<body>
<h1>Single page website</h1>
</body>
</html>
```
