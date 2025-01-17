package config

type SNMPParameters struct {
	Host                     string `yaml:"host"`
	HostRange                string `yaml:"host_range"`
	UserName                 string `yaml:"userName"`
	AuthenticationProtocol   string `yaml:"AuthenticationProtocol"`
	AuthenticationPassphrase string `yaml:"AuthenticationPassphrase"`
	PrivacyProtocol          string `yaml:"PrivacyProtocol"`
	PrivacyPassphrase        string `yaml:"PrivacyPassphrase"`
}
