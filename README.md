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
    http.HandleFunc("/", static.HandlerFunc("static_files", nil))
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

