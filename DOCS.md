# Nstatic documentation

- [Getting started](#getting-started)
- [Server side includes](#server-side-includes)
- [URL File routes](#url-file-routes)

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

## URL file routes

Here are some examples of how nstatic resolves files from URLs
Notice that a dollar sign can be used as a directory separator.
A '?' can be used as a wildcard suffix.

Let's say your root is the diretory "website_root".

```
https://localhost:8000/contact      => website_root/contact.html
https://localhost:8000/docs/faq     => website_root/docs/faq.html
https://localhost:8000/docs/faq     => website_root/docs/faq/index.html
https://localhost:8000/docs/faq     => website_root/docs$faq.html
https://localhost:8000/hello/jello  => website_root/hello/index.html
https://localhost:8000/user/156     => website_root/user/156.html
https://localhost:8000/user/156     => website_root/user$156.html
https://localhost:8000/user/156     => website_root/user$?.html
https://localhost:8000/user/1025    => website_root/user$?.html
```
