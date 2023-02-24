package main

import (
	"log"
	"os"

	"check-pwd/cli"
)

func main() {
	if err := cli.Run(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
