# ZaNetworkTool

802.1X EAP 网络认证工具

## 依赖

- Go 1.18+
- libpcap (macOS/Linux) 或 WinPcap/Npcap (Windows)

## 构建

```bash
go build ./...
```

## 使用

```bash
# 列出网络接口
go run ./cmd/device

# 捕获 EAP 凭证
go run ./cmd/hack -i <interface>

# 使用捕获的凭证进行认证
go run ./cmd/auth -interface <interface> -mac <mac-address>
```

### EAP 镜像工具

用于在两台机器间中继 EAP 认证。机器 A 有 EAP 客户端，机器 B 没有客户端但需要认证。

```
认证服务器 <--802.1X--> 机器B(client) <--TCP--> 机器A(server) <--802.1X--> A的EAP客户端
```

```bash
# 机器 A (有 EAP 客户端, IP: 192.168.1.100)
go run ./cmd/mirror -mode server -interface en0 -mac <supplicant-mac> -listen :8021

# 机器 B (需要认证)
go run ./cmd/mirror -mode client -interface en0 -mac <local-mac> -server 192.168.1.100:8021
```

## 参考

- [802.1X](https://baike.baidu.com/item/802.1x/5635474?fr=aladdin)
- [gopacket](https://godoc.org/github.com/google/gopacket)
