// A Go program that carries PHP's header text but is not PHP.
package main

import (
	"fmt"
	"net/http"
	"os"
)

const banner = "X-Powered-By: PHP/8.3.20"
const zend = "Zend Engine v4.3.20, Copyright (c) Zend Technologies"

func main() {
	h := http.Header{}
	h.Set("X-Powered-By", "PHP/8.3.20")
	fmt.Println(banner, zend, len(h), os.Args)
}
