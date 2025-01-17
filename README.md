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
### logic.sh 脚本对接收文本进行处理
