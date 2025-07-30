# Nstatic documentation

## Getting started

The most basic website:

**main.go**

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

**website_root/index.html**

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

## Server side includes

Here's an example of header/footer style includes

**website_root/index.html**

```html
{{ template "_header.html" "Title" "Homepage" }}

<h1>Single page website</h1>

{{ template "_footer.html" }}
```

**website_root/_header.html**

```html
<html>
<head>
<title>{{ .Title }}</title>
</head>
<body>
```


**website_root/_footer.html**

```html
</body>
</html>
```
