# RARP Consumer 批量部署工具

此目录包含 RARP Consumer 服务的完整部署解决方案，支持批量部署到多个节点。

## 快速开始

### 1. 准备工作
确保你有目标节点的 SSH 访问权限，并且目标节点支持 systemd。

### 2. 配置节点信息
编辑 `node_config.txt`：
```bash
# stage1 - 服务配置
service_name="rarp-consumer"
service_file="rarp-consumer.service" 
install_script="deploy_service.sh"

# stage2 - 节点配置 (ip,username,password)
192.168.79.23,root,your_password
192.168.72.171,root,your_password
```

### 3. 执行部署
```bash
# 验证配置（推荐先执行）
./batch_deploy.sh node_config.txt ./binaries/ --dry-run

# 实际部署
./batch_deploy.sh node_config.txt ./binaries/
```


##  文件说明

| 文件/目录 | 说明 |
|-----------|------|
| `batch_deploy.sh` | **主部署脚本** - 批量部署工具 |
| `deploy_service.sh` | **安装脚本** - 单节点服务安装 |
| `rarp-consumer.service` | **systemd服务文件** |
| `node_config.txt` | **配置文件** - 节点和服务配置 |
| `binaries/` | **二进制文件目录** - 包含不同架构的可执行文件 |


## 安装内容

部署成功后，每个节点将包含：

### 服务组件
- **主程序**: `/usr/local/bin/rarp_consumer_static`
- **systemd服务**: `/etc/systemd/system/rarp-consumer.service`
- **管理脚本**: `/usr/local/bin/rarp-consumer-ctl` 

### rarp-consumer-ctl 命令行工具

`rarp-consumer-ctl` 是自动生成的服务管理工具，提供便捷的服务操作：

```bash
# 基本操作
rarp-consumer-ctl start      # 启动服务
rarp-consumer-ctl stop       # 停止服务  
rarp-consumer-ctl restart    # 重启服务
rarp-consumer-ctl status     # 查看状态

# 管理操作
rarp-consumer-ctl enable     # 设置开机自启
rarp-consumer-ctl disable    # 禁用开机自启
rarp-consumer-ctl logs       # 查看实时日志
```
## ️ 服务管理

### 使用 systemctl (原生方式)
```bash
sudo systemctl status rarp-consumer     # 查看状态
sudo systemctl start rarp-consumer      # 启动服务
sudo systemctl stop rarp-consumer       # 停止服务
sudo systemctl restart rarp-consumer    # 重启服务
sudo journalctl -u rarp-consumer -f     # 查看日志
```

### 使用 rarp-consumer-ctl (推荐)
```bash
rarp-consumer-ctl status    # 查看状态 (自动sudo)
rarp-consumer-ctl start     # 启动服务
rarp-consumer-ctl logs      # 查看实时日志
```

## 部署报告

部署完成后会生成详细报告：
- **成功节点列表** - 包含架构、耗时等信息
- **失败节点详情** - 错误信息和排查建议  
- **服务管理命令** - 后续维护参考

### 查看详细日志
```bash
# 在目标节点上查看服务日志
sudo journalctl -u rarp-consumer -f

# 查看部署报告
cat deployment_report_YYYYMMDD_HHMMSS.txt
```

##  依赖要求

### 控制节点 (运行部署脚本的机器)
- bash shell
- ssh, scp 工具
- sshpass (可选，用于密码认证)