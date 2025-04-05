package configs

type Config struct {
	HTTPAddr  string                  `yaml:"http-addr"`
	HTTPSAddr string                  `yaml:"https-addr"`
	Certs     string                  `yaml:"certs"`
	ApiAddr   string                  `yaml:"api-addr"`
	Default   DomainConfig            `yaml:"default"`
	Domains   map[string]DomainConfig `yaml:"domains"`
}

// DomainConfig 定义域名配置
type DomainConfig struct {
	Target string `yaml:"target"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}
