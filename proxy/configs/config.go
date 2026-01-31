package configs

type Config struct {
	HTTPAddr    string `yaml:"http-addr"`
	HTTPSAddr   string `yaml:"https-addr"`
	Certs       string `yaml:"certs"`
	ApiAddr     string `yaml:"api-addr"`
	AutoSetCert bool   `yaml:"auto-set-cert"` // 自动申请证书

	Default DomainConfig            `yaml:"default"`
	Domains map[string]DomainConfig `yaml:"domains"`
}

type DomainConfig struct {
	Target       string `yaml:"target"`
	Cert         string `yaml:"cert"`
	Key          string `yaml:"key"`
	Sni          string `yaml:"sni"`
	Origin       string `yaml:"origin"`
	ForceHttps   bool   `yaml:"force-https"`
	DisableHttps bool   `yaml:"disable-https"`
}
