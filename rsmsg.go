package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// 配置数据库连接信息
type DBConfig struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	DBName   string `json:"dbname"`
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

// 连接到 MySQL 数据库
func connectToMySQL(config *DBConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", config.User, config.Password, config.Host, config.Port, config.DBName)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("could not connect to Clickhouse: %v", err)
	}
	return db, nil
}

// 插入 trap 数据到数据库
func insertTrapData(db *sql.DB, ip, level, device_oid, labels string) error {
	query := `INSERT INTO hcs_alert.trap_log (trap_ip, level, labels, device_oid) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, ip, level, labels, device_oid)
	if err != nil {
		return fmt.Errorf("could not insert data into Clickhouse: %v", err)
	}
	return nil
}

// 处理接收消息的逻辑
func messageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// 读取消息内容
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// 按空格切分消息
		parts := strings.Fields(string(body))
		if len(parts) < 4 {
			http.Error(w, "Invalid message format", http.StatusBadRequest)
			return
		}

		// 提取字段
		ip := parts[0]
		level := parts[1]
		deviceOid := parts[2]
		labels := strings.Join(parts[3:], " ") // 余下的内容作为 labels

		// 插入数据到 MySQL
		insertTrapDataToMySQL(ip, level, deviceOid, labels)
		if err != nil {
			http.Error(w, "Failed to insert data into database", http.StatusInternalServerError)
			return
		}

		fmt.Printf("Received and stored trap: ip=%s, level=%s, device_oid=%s, labels=%s\n", ip, level, deviceOid, labels)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Message received and stored"))
	} else {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
	}
}

func insertTrapDataToMySQL(ip, labels, level, device_oid string) {
	dbconfig, err := readDBConfig("db.json")
	if err != nil {
		log.Printf("Error reading DB config: %v", err)
		return
	}

	db, err := connectToMySQL(dbconfig)
	if err != nil {
		log.Printf("Error connecting to the database: %v", err)
		return
	}
	defer db.Close()

	if err := insertTrapData(db, ip, level, device_oid, labels); err != nil {
		log.Printf("Error inserting data into Clickhouse: %v", err)
	}
}

func main() {
	// 设置路由
	http.HandleFunc("/message", messageHandler)

	// 启动 HTTP 服务器
	port := 9055
	fmt.Printf("Server is listening on port %d\n", port)
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatalf("Failed to start server: %s", err)
	}
}
