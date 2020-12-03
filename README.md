# nstatic

Not a static website framework

## Example

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


