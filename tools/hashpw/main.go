package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/slavasuhoveev/shelf-auth/internal/security"
)

func main() {
	var pw string
	var pepper string
	flag.StringVar(&pw, "password", "", "plain password")
	flag.StringVar(&pepper, "pepper", "", "optional app-level pepper")
	flag.Parse()

	if pw == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./tools/hashpw -password <pw> [-pepper <pepper>]")
		os.Exit(2)
	}

	opts := security.DefaultOptions()
	if pepper != "" {
		opts.Pepper = []byte(pepper)
	}
	hash, err := security.HashPassword(pw, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash error:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
