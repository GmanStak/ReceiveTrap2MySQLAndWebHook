package core

import (
	"github.com/spf13/viper"
	"log"
	"snmpTrapReceive/global"
	"snmpTrapReceive/utils"
)

func Viper() *viper.Viper {
	var configPath = "config.yaml"
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")
	err := v.ReadInConfig()
	if err != nil {
		panic("error config file: %s ")
	}
	err = v.Unmarshal(&global.G_Config)
	if err != nil {
		panic("配置文件解析出错")
	}

	if global.G_Config.Encrypt {
		for i, SNMPParameter := range global.G_Config.SNMPParameters {
			global.G_Config.SNMPParameters[i].AuthenticationPassphrase, _ = utils.Descrypt(SNMPParameter.AuthenticationPassphrase)
			global.G_Config.SNMPParameters[i].PrivacyPassphrase, _ = utils.Descrypt(SNMPParameter.PrivacyPassphrase)
		}
	}

	log.Println("配置读取成功")
	return v
}
