package main

import (
	"fmt"
	"log"
	"os"
	"snmpTrapReceive/core"
)

// 开启日志
func init() {
	logFile, err := os.OpenFile("./log.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("open log file failed, err:", err)
		return
	}
	log.SetOutput(logFile)
	log.SetPrefix("[snmpTrapReceive]")
	log.SetFlags(log.Lshortfile | log.Lmicroseconds | log.Ldate)
}

func main() {
	core.Viper()
	core.Run()
}
