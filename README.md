# snmpTrapReceive


## 结构
```shell
├─config 配置包 
├─core 核心组件(zap, viper, server)的初始化
├─global 全局对象
└─utils 工具方法
```


### 可配置经过身份验证的 SnmpV3 连接使用的身份验证协议(AuthenticationProtocol)
+ NoAuth
+ MD5
+ SHA224
+ SHA256
+ SHA384
+ SHA512
### 可配置私有 SnmpV3 连接使用的隐私协议(PrivacyProtocol)
+ NoPriv
+ DES
+ AES
+ AES192
+ AES256
+ AES192C
+ AES256C
### 增加数据写入
数据库文件：db.json
```shell
{
  "user": "admin",
  "password": "admin",
  "host": "10.10.10.1",
  "port": "3306",
  "dbname": "alert"
}
```
### 配置文件 config.yaml
```shell
Listen: '127.0.0.1:162'
SNMPParameters:
  - HostRange: 10.10.1.1-10.10.10.1
    userName: admin
    AuthenticationProtocol: SHA256
    AuthenticationPassphrase: admin123
    PrivacyProtocol: AES
    PrivacyPassphrase: admin123
  - host: 10.10.1.1
    userName: trapadmin
    AuthenticationProtocol: SHA256
    AuthenticationPassphrase: trapadmin123
    PrivacyProtocol: AES
    PrivacyPassphrase: trapadmin123
  - host: 10.10.1.2
    userName: netadmin
    AuthenticationProtocol: SHA256
    AuthenticationPassphrase: netadmin123
    PrivacyProtocol: AES
    PrivacyPassphrase: netadmin123
  - host: default
    userName: defaultadmin
    AuthenticationProtocol: SHA256
    AuthenticationPassphrase: defaultadmin123
    PrivacyProtocol: AES
    PrivacyPassphrase: defaultadmin123
v2IP: 127.0.0.1
v2Port: 9514
wbIP: 10.10.10.1
wbPort: 9055
```
匹配流程：
接收获取IP ---> 通过IP或在ip范围内则获取对应认证信息 ---> 解析后存入MySQL数据库并发送到对应的webhook地址
### logic.sh 脚本对接收文本进行处理
```shell
#!/bin/bash -e
 ip=$1
 message=$2
 ARR=($message)
 if [[ ${ARR[2]} =~ ^\.1\.3\.6\.1\.4\.1\.37945 ]];then
         level=`exec ./include-snmp/pass.sh ${ARR[2]}`
 else
         level=5
 fi
 echo $level $message
```
返回值level和message会返给程序进行写入数据库和webhook接口
### 注意：使用webhook接收时必须先启动webhook程序，再启动snmp接收程序
