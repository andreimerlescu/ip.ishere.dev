package main

import (
	"fmt"
	"html/template"
	"os"
	"strings"
)

func about() {
	fmt.Printf("%s %s\n", AppName, Version())
	domain := fmt.Sprintf("https://%s", *figs.String(argDomain))
	format := "\t%s%s%s\n"
	fmt.Printf("%s\n", "CURL Usage:")
	fmt.Printf("\t%s%s\n", `curl -s -L `, domain)
	fmt.Printf(format, `curl -sL`, domain, `/read.ini`)
	fmt.Printf(format, `curl -sL `, domain, `/read.json`)
	fmt.Printf(format, `curl -sL `, domain, `/read.yaml`)
	fmt.Printf(format, `curl -sL `, domain, `/read.json | jq -r '.ipv4'`)
	fmt.Printf(format, `curl -sL `, domain, ` | grep IPv4 | awk '{print $2}'`)
	fmt.Println("")
}

func renderTemplates() error {
	var err error
	indexTemplate, err = template.New("index").Parse(TemplateBytesIndex)
	return err
}

func Version() string {
	if len(currentVersion) == 0 {
		versionBytes, err := versionBytes.ReadFile("VERSION")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to read embedded VERSION file: %v", err.Error())
			return "v0.0.0"
		}
		currentVersion = strings.TrimSpace(string(versionBytes))
	}
	return currentVersion
}
