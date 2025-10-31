# JumpServer Debug Workflow Examples

本目录包含跳板机调试工作流的示例脚本。

## 文件说明

| 文件 | 用途 | 需要密码 |
|------|------|----------|
| `jumpserver_login.expect` | 交互式登录到目标机器 | 跳板机 + 文件传输 |
| `run_remote_test.expect` | 自动化执行远程测试脚本 | 跳板机 + 文件传输 |
| `batch_upload.sh` | 批量上传文件到文件传输跳板机 | 文件传输 |
| `batch_download.sh` | 批量下载结果文件 | 文件传输 |

## 快速开始

### 1. 交互式登录

最简单的方式，会提示输入密码：

```bash
./jumpserver_login.expect
```

登录后可以手动执行命令，支持完整的交互式 shell。

### 2. 自动化测试

首先准备测试脚本并上传：

```bash
# 创建测试脚本
cat > /tmp/my_test.sh << 'EOF'
#!/bin/bash
echo "Running test on $(hostname)"
bash --version
EOF

# 上传到文件传输跳板机
./batch_upload.sh /tmp/my_test.sh
```

然后执行自动化测试：

```bash
# 方式 1: 提示输入密码
read -sp "Jump password: " JUMP_PASS; echo
read -sp "File transfer password: " FILE_PASS; echo
./run_remote_test.expect "$JUMP_PASS" "$FILE_PASS" my_test.sh
```

### 3. 批量上传文件

```bash
# 上传单个文件
./batch_upload.sh /tmp/script1.sh

# 上传多个文件
./batch_upload.sh /tmp/script1.sh /tmp/script2.sh /tmp/script3.sh

# 上传当前目录所有 .sh 文件
./batch_upload.sh *.sh
```

### 4. 批量下载结果

```bash
# 下载所有测试结果文件
./batch_download.sh "test_results_*.txt"

# 下载所有 .log 文件
./batch_download.sh "*.log"

# 下载所有文件
./batch_download.sh "*"
```

## 安全使用指南

### ✅ 推荐做法

**方式 1: 运行时输入密码**（最安全）

```bash
# 使用包装脚本
cat > run_test.sh << 'EOF'
#!/bin/bash
read -sp "Enter jumpserver password: " JUMP_PASS
echo
read -sp "Enter file transfer password: " FILE_PASS
echo
./run_remote_test.expect "$JUMP_PASS" "$FILE_PASS" "$@"
unset JUMP_PASS FILE_PASS
EOF
chmod +x run_test.sh

./run_test.sh my_test.sh
```

**方式 2: 使用密码管理器**

```bash
# 如果使用 pass (password-store)
JUMP_PASS=$(pass show work/jumpserver)
FILE_PASS=$(pass show work/file-transfer)
./run_remote_test.expect "$JUMP_PASS" "$FILE_PASS" test.sh
unset JUMP_PASS FILE_PASS
```

### ❌ 不推荐做法

不要硬编码密码：

```bash
# ❌ 不要这样做！
./run_remote_test.expect "my_password" "my_other_password" test.sh

# ❌ 不要这样做！
export JUMP_PASSWORD="my_password"
```

不要将包含密码的文件提交到 git：

```bash
# ❌ 不要创建这样的文件并提交
cat > credentials.sh << 'EOF'
JUMP_PASSWORD="my_password"
FILE_PASSWORD="my_other_password"
EOF
```

## 常见场景

### 场景 1: 快速测试单个脚本

```bash
# 1. 准备脚本
echo '#!/bin/bash; echo "Hello from $(hostname)"' > /tmp/hello.sh

# 2. 上传
./batch_upload.sh /tmp/hello.sh

# 3. 运行
read -sp "Jump pass: " J; echo
read -sp "File pass: " F; echo
./run_remote_test.expect "$J" "$F" hello.sh
unset J F
```

### 场景 2: 诊断脚本系列测试

```bash
# 准备多个诊断脚本
./batch_upload.sh \
    diagnose_bash.sh \
    test_performance.sh \
    collect_logs.sh

# 依次执行
for script in diagnose_bash.sh test_performance.sh collect_logs.sh; do
    echo "Running $script..."
    read -sp "Jump pass: " J; echo
    read -sp "File pass: " F; echo
    ./run_remote_test.expect "$J" "$F" "$script"
    unset J F
    echo "---"
done

# 下载所有结果
./batch_download.sh "test_results_*.txt"
```

### 场景 3: 长时间运行的监控脚本

```bash
# 创建监控脚本
cat > /tmp/monitor.sh << 'EOF'
#!/bin/bash
# 监控 10 分钟
for i in {1..60}; do
    echo "[$i/60] $(date): Load $(uptime | awk -F'load average:' '{print $2}')"
    sleep 10
done
EOF

# 上传
./batch_upload.sh /tmp/monitor.sh

# 运行（注意设置足够长的超时时间）
# 在 run_remote_test.expect 中设置: set timeout 600
read -sp "Jump pass: " J; echo
read -sp "File pass: " F; echo
./run_remote_test.expect "$J" "$F" monitor.sh
unset J F
```

## 自定义配置

所有脚本开头都有配置变量，可以根据实际环境修改：

```bash
# 在 jumpserver_login.expect 中
set jump_host "jump.smartx.com"
set jump_port "2222"
set jump_user "your_username"          # 修改这里
set target_host "19.95"                 # 修改这里
set target_workdir "/home/user/work"   # 修改这里
```

## 故障排查

### 问题 1: expect: command not found

```bash
# macOS
brew install expect

# Ubuntu/Debian
sudo apt-get install expect

# CentOS/RHEL
sudo yum install expect
```

### 问题 2: 登录超时

增加 expect 脚本中的超时时间：

```expect
set timeout 120  # 改为 120 秒或更长
```

### 问题 3: 密码包含特殊字符

使用单引号传递密码，或转义特殊字符：

```bash
# 单引号
./run_remote_test.expect 'p@$$w0rd!#' 'p@$$w0rd!#' test.sh

# 或使用读取输入方式（推荐）
read -sp "Password: " PASS
echo
./run_remote_test.expect "$PASS" ...
```

### 问题 4: SSH 密钥冲突

如果有多个 SSH 密钥，可能需要指定：

```bash
ssh -i ~/.ssh/specific_key user@host
```

在 expect 脚本中：

```expect
spawn ssh -i ~/.ssh/specific_key ${user}@${host}
```

## 更多资源

- [主文档](../jumpserver-debug-workflow.md) - 完整的工作流说明
- [Expect 教程](https://likegeeks.com/expect-command/) - Expect 语法和技巧
- [SSH JumpHost](https://www.redhat.com/sysadmin/ssh-proxy-bastion-proxyjump) - SSH 跳板配置
