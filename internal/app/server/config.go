package server

type Config struct {
	IP_addr string `toml:"ip_addr"`
	Log_lvl string `toml:"log_lvl"`
}

func NewConfig() *Config {
	return &Config{
		IP_addr: ":3000",
		Log_lvl: "debug",
	}
}
