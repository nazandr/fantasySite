package main

import (
	"flag"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/nazand/fantacySite/internal/app/server"
)

var (
	configPath string
)

func init() {
	flag.StringVar(&configPath, "config-path", "config/config.toml", "path to config file")
}

func main() {
	flag.Parse()

	config := server.NewConfig()

	_, err := toml.DecodeFile(configPath, config)
	if err != nil {
		log.Fatal(err)
	}

	server := server.New(config)

	if err := server.Start(); err != nil {
		log.Fatal(err)
	}

}
