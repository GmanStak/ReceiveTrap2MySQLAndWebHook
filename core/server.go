package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	g "github.com/gosnmp/gosnmp"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"snmpTrapReceive/config"
	"snmpTrapReceive/global"
	"strings"
	"time"
)

type DBConfig struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	DBName   string `json:"dbname"`
}

type Config struct {
	Listen         string           `yaml:"listen"`
	SNMPParameters []SNMPParameters `yaml:"snmp"`
	V2IP           string           `yaml:"v2IP"`
	V2Port         uint16           `yaml:"v2Port"`
	Encrypt        bool             `yaml:"encrypt"`
}

type SNMPParameters struct {
	Host                     string `yaml:"host"`
	HostRange                string `yaml:"host_range"`
	UserName                 string `yaml:"userName"`
	AuthenticationProtocol   string `yaml:"AuthenticationProtocol"`
	AuthenticationPassphrase string `yaml:"AuthenticationPassphrase"`
	PrivacyProtocol          string `yaml:"PrivacyProtocol"`
	PrivacyPassphrase        string `yaml:"PrivacyPassphrase"`
}

func Run() {
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	tl := g.NewTrapListener()
	tl.OnNewTrap = myTrapHandler
	tl.Params = createDefaultSNMPConfig()

	snmps := getSNMPs()

	err := tl.ListenNew(global.G_Config.Listen, snmps)
	if err != nil {
		log.Panicf("Error in listen: %s", err)
	}
}

// 创建默认 SNMP 配置
func createDefaultSNMPConfig() *g.GoSNMP {
	return &g.GoSNMP{
		Version:       g.Version3,
		Timeout:       time.Duration(30) * time.Second,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		SecurityParameters: &g.UsmSecurityParameters{
			UserName:                 "user",
			AuthenticationProtocol:   g.SHA512,
			AuthenticationPassphrase: "password",
			PrivacyProtocol:          g.AES256C,
			PrivacyPassphrase:        "password",
		},
	}
}

// 获取 SNMP 配置列表
func getSNMPs() []g.GoSNMP {
	var snmps []g.GoSNMP
	for _, snmpParam := range global.G_Config.SNMPParameters {
		snmps = append(snmps, *createSNMPConfig(&snmpParam))
	}
	return snmps
}

// 根据 SNMP 参数创建 SNMP 配置
func createSNMPConfig(snmpParam *config.SNMPParameters) *g.GoSNMP {
	return &g.GoSNMP{
		Version:       g.Version3,
		Timeout:       time.Duration(30) * time.Second,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		SecurityParameters: &g.UsmSecurityParameters{
			UserName:                 snmpParam.UserName,
			AuthenticationProtocol:   getAuthProtocol(snmpParam.AuthenticationProtocol),
			AuthenticationPassphrase: snmpParam.AuthenticationPassphrase,
			PrivacyProtocol:          getPrivProtocol(snmpParam.PrivacyProtocol),
			PrivacyPassphrase:        snmpParam.PrivacyPassphrase,
		},
	}
}

// Trap 处理函数
func myTrapHandler(packet *g.SnmpPacket, addr *net.UDPAddr) {
	log.Printf("Received trap data from %s\n", addr.IP)

	// 获取请求的 host（IP 地址）
	receivedHost := addr.IP.String()

	// 查找与接收到的 host 匹配的认证信息
	matchingSNMPParam := findMatchingSNMPParam(receivedHost)
	if matchingSNMPParam == nil {
		log.Printf("No matching SNMP config found for host: %s, using default config", receivedHost)
		// 使用 default 配置作为默认认证信息
		matchingSNMPParam = findDefaultSNMPParam()
	}

	// 如果没有找到默认配置，也返回
	if matchingSNMPParam == nil {
		log.Printf("No default SNMP config found, dropping trap")
		return
	}

	// 创建新的 GoSNMP 配置，使用匹配的认证信息
	log.Printf("Matched SNMP config for host %s", receivedHost)
	snmp := createSNMPConfig(matchingSNMPParam)

	// 处理 trap 数据
	processTrapData(packet, addr, snmp)
}

func getAuthProtocol(protocol string) g.SnmpV3AuthProtocol {
	switch protocol {
	case "NoAuth":
		return g.NoAuth
	case "MD5":
		return g.MD5
	case "SHA":
		return g.SHA
	case "SHA224":
		return g.SHA224
	case "SHA256":
		return g.SHA256
	case "SHA384":
		return g.SHA384
	case "SHA512":
		return g.SHA512
	}
	return g.NoAuth
}

func getPrivProtocol(protocol string) g.SnmpV3PrivProtocol {
	switch protocol {
	case "NoPriv":
		return g.NoPriv
	case "DES":
		return g.DES
	case "AES":
		return g.AES
	case "AES192":
		return g.AES192
	case "AES256":
		return g.AES256
	case "AES192C":
		return g.AES192C
	case "AES256C":
		return g.AES256C
	}
	return g.NoPriv
}

// 判断 IP 是否在范围内
func isIPInRange(ip string, rangeStr string) bool {
	// 如果是单个 IP（没有范围分隔符），直接匹配
	if !strings.Contains(rangeStr, "-") {
		return ip == rangeStr
	}

	// 分割范围
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return false // 无效范围
	}

	startIP := net.ParseIP(parts[0])
	endIP := net.ParseIP(parts[1])
	targetIP := net.ParseIP(ip)

	// 确保 IP 地址合法
	if startIP == nil || endIP == nil || targetIP == nil {
		return false
	}

	// 比较范围
	return bytes.Compare(targetIP, startIP) >= 0 && bytes.Compare(targetIP, endIP) <= 0
}

// 查找匹配的 SNMP 配置
func findMatchingSNMPParam(host string) *config.SNMPParameters {
	for _, snmpParam := range global.G_Config.SNMPParameters {
		if snmpParam.Host == host || isIPInRange(host, snmpParam.HostRange) {
			return &snmpParam
		}
	}
	return nil
}

// 查找默认的 SNMP 配置
func findDefaultSNMPParam() *config.SNMPParameters {
	for _, snmpParam := range global.G_Config.SNMPParameters {
		if snmpParam.Host == "default" {
			return &snmpParam
		}
	}
	return nil
}

// 处理 trap 数据并发送到 syslog
func processTrapData(packet *g.SnmpPacket, addr *net.UDPAddr, snmp *g.GoSNMP) {
	var oidV2, valV2, VirtualOidV2 = "", "", ""
	for i, variable := range packet.Variables {
		val := processTrapVariable(variable)
		if val == "" {
			valV2 = valV2 + "null" + " "
		} else {
			valV2 = valV2 + val + " "
		}
		if i == 0 {
			VirtualOidV2 = variable.Name
		}
		log.Printf("- oid[%d]: %s (%s) = %v \n", i, variable.Name, variable.Type, val)
	}

	if oidV2 == "" {
		oidV2 = VirtualOidV2
	}

	if len(valV2) > 0 {
		valV2 = valV2[:len(valV2)-1]
	}

	// 增加实际转发设备的ip信息到trap头部
	result_val := fmt.Sprintf("%s %s", addr.IP.String(), valV2)
	log.Printf("- v2Send: %s  = %v \n", oidV2, result_val)

	// 处理消息并解析
	ip, labels, level, device_oid := processMessage(result_val)
	log.Printf("Parsed data: ip: %s, level: %s, labels: %s, device_oid: %s", ip, level, labels, device_oid)

	// 插入数据到 MySQL
	insertTrapDataToClickhouse(ip, labels, level, device_oid)
	// 插入远程webhhok
	insertTrap2webhook(ip, level, device_oid, labels)
}

// 处理 trap 变量
func processTrapVariable(variable g.SnmpPDU) string {
	var val string
	switch variable.Type {
	case g.OctetString:
		val = string(variable.Value.([]byte))
	case g.ObjectIdentifier:
		val = fmt.Sprintf("%s", variable.Value)
	case g.TimeTicks:
		a := g.ToBigInt(variable.Value)
		timeObj := time.Unix((*a).Int64(), 0)
		val = timeObj.Format("2006-01-02 15:04:05")
	default:
		a := g.ToBigInt(variable.Value)
		val = fmt.Sprintf("%d", (*a).Int64())
	}
	return val
}

// 处理消息并解析
func processMessage(message string) (string, string, string, string) {
	parts := strings.Fields(message)
	if len(parts) < 1 {
		log.Printf("Invalid data format")
		return "", "", "0", ""
	}
	ip := parts[0]
	device_oid := parts[3]
	new_message := strings.Join(parts[1:], " ")
	level, newMessage := getLevelFromMessage(ip, new_message)
	log.Printf("Parsed message: ip: %s, level: %s, message: %s", ip, level, newMessage)
	return ip, newMessage, level, device_oid
}

// 调用 shell 脚本获取 level 和 message
func getLevelFromMessage(ip, message string) (string, string) {
	cmd := exec.Command("./logic.sh", ip, message)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error executing shell command: %v", err)
		return "0", ""
	}
	var level string
	var nMessage string
	_, err = fmt.Sscanf(string(output), "%s %s", &level, &nMessage)
	if err != nil {
		log.Printf("Error parsing level from shell output: %v", err)
	}
	nMessage = strings.Join(strings.Fields(string(output))[1:], " ")
	return level, nMessage
}

// 插入数据到 Clickhouse
func insertTrapDataToClickhouse(ip, labels, level, device_oid string) {
	dbconfig, err := readDBConfig("db.json")
	if err != nil {
		log.Printf("Error reading DB config: %v", err)
		return
	}

	db, err := connectToClickhouse(dbconfig)
	if err != nil {
		log.Printf("Error connecting to the database: %v", err)
		return
	}
	defer db.Close()

	if err := insertTrapData(db, ip, labels, level, device_oid); err != nil {
		log.Printf("Error inserting data into Clickhouse: %v", err)
	}
}

// 读取数据库配置
func readDBConfig(dbfilename string) (*DBConfig, error) {
	file, err := ioutil.ReadFile(dbfilename)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %v", err)
	}
	var config DBConfig
	err = json.Unmarshal(file, &config)
	if err != nil {
		return nil, fmt.Errorf("could not parse JSON: %v", err)
	}
	return &config, nil
}

// 连接到 Clickhouse 数据库
func connectToClickhouse(config *DBConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", config.User, config.Password, config.Host, config.Port, config.DBName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("could not connect to Clickhouse: %v", err)
	}
	return db, nil
}

// 插入 trap 数据到数据库
func insertTrapData(db *sql.DB, ip, labels, level, device_oid string) error {
	query := `INSERT INTO hcs_alert.trap_log (trap_ip, level, labels, device_oid) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, ip, level, labels, device_oid)
	if err != nil {
		return fmt.Errorf("could not insert data into Clickhouse: %v", err)
	}
	return nil
}

// 发送trap到webhook
func insertTrap2webhook(ip, level, device_oid, labels string) error {
	trapms := fmt.Sprintf("%s %s %s %s", ip, level, device_oid, labels)
	url := fmt.Sprintf("http://%s:%s/message", global.G_Config.WbIP, global.G_Config.WbPort)
	// 要发送的消息
	message := []byte(trapms)

	// 创建请求主体
	reqBody := bytes.NewBuffer(message)

	// 发送 POST 请求
	resp, err := http.Post(url, "text/plain", reqBody)
	if err != nil {
		log.Printf("Failed to send message: %s", err)
	}
	defer resp.Body.Close()

	// 打印响应状态
	fmt.Printf("Response status: %s\n", resp.Status)
	return nil
}
