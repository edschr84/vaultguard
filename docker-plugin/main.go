package main

import (
	"fmt"
	"os"

	"github.com/vaultguard/docker-plugin/helper"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: docker-credential-vaultguard <get|store|erase|list>")
		os.Exit(1)
	}

	h, err := helper.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	switch os.Args[1] {
	case "get":
		err = h.Get()
	case "store":
		err = h.Store()
	case "erase":
		err = h.Erase()
	case "list":
		err = h.List()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
