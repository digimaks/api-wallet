// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"log"
	"os"
	"regexp"

	"github.com/lafriks-fork/goas"
)

const openAPIJSONFile = "openapi.json"

func main() {
	p, err := goas.NewParser("../", "openapi.go", "", false)
	if err != nil {
		log.Fatalf("Can not initialize goas generator: %v", err)
	}

	err = p.CreateOASFile(openAPIJSONFile)
	if err != nil {
		log.Fatalf("Error while generating openapi.json: %v", err)
	}

	input, err := os.ReadFile(openAPIJSONFile)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	m1 := regexp.MustCompile(`(?s)"Decimal"\:\s\{(.*?\}.*?\}.*?\}.*?\})`)
	output := m1.ReplaceAllString(string(input), `"Decimal": {"type": "number"}`)

	if err = os.WriteFile(openAPIJSONFile, []byte(output), 0o600); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
