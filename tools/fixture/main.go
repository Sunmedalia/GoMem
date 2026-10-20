package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Sunmedalia/GoMem/internal/testfixture"
)

func main() {
	dir := flag.String("out", ".cache/fixtures", "Synthetic output directory")
	flag.Parse()
	for _, platform := range []string{"linux", "windows"} {
		f, err := testfixture.Write(*dir, platform)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(f)
	}
}
