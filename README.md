# static

**Very simple** static website handler for Go.

## Example

```go
package main

import (
    "net/http"
    "log"

    "github.com/tidwall/static"
)

func main() {
    handler, err := static.NewHandlerFunc("static_files", nil)
    if err != nil {
        log.Fatal(err)
    }
    http.HandleFunc("/", handler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

