package config

type Config struct {
	Listen         string           `yaml:"listen"`
	SNMPParameters []SNMPParameters `yaml:"snmp"`
	V2IP           string           `yaml:"v2IP"`
	V2Port         uint16           `yaml:"v2Port"`
	Encrypt        bool             `yaml:"encrypt"`
	WbIP           string           `yaml:"wbIP"`
	WbPort         string           `yaml:"wbPort"`
}
