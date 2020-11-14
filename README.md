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
    vars := map[string]string{
        "MyVar": "Hi!", // Replaces all occurrences of {{{MyVar}}} with "Hi!"
    }
    http.HandleFunc("/", static.HandlerFunc("static_files", vars))
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

