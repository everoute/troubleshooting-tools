# 跳板机远程调试工作流指南

## 概述

本文档描述如何通过跳板机（JumpServer）访问内部机器进行远程调试，包括文件传输和自动化测试。

## 架构

```
本地机器
  ↓ SSH (port 2222)
跳板机 (jump.smartx.com)
  ↓ 选择目标
内部机器 (hygon-node-19-95)
  ↑ SCP
文件传输跳板机 (192.168.17.20)
```

## 环境变量配置

首先设置环境变量以便脚本使用：

```bash
# 跳板机配置
export JUMP_HOST="jump.smartx.com"
export JUMP_PORT="2222"
export JUMP_USER="chengcheng.luo"
export JUMP_PASSWORD=""  # 运行时输入

# 目标机器配置
export TARGET_HOST="19.95"  # JumpServer 中的简称
export TARGET_HOST_FULL="hygon-node-19-95"
export TARGET_USER="smartx"
export TARGET_WORKDIR="/home/smartx/lcc"

# 文件传输跳板机配置
export FILE_JUMP_HOST="192.168.17.20"
export FILE_JUMP_USER="root"
export FILE_JUMP_DIR="/root/lcc"
export FILE_JUMP_PASSWORD=""  # 运行时输入
```

## 工作流程

### 1. 文件传输流程

#### 1.1 上传文件到文件传输跳板机

从本地上传测试文件到中转服务器（免密）：

```bash
# 单个文件
scp /path/to/local/file.sh ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/

# 多个文件
scp file1.sh file2.sh file3.sh ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/

# 整个目录
scp -r /path/to/directory ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/
```

**示例**：
```bash
# 上传测试脚本
scp /tmp/test_script.sh root@192.168.17.20:/root/lcc/
scp ebpf-tools/cpu/cpu_monitor.sh root@192.168.17.20:/root/lcc/
```

#### 1.2 从文件传输跳板机下载到目标机器

在目标机器上从中转服务器下载（需要密码）：

```bash
# 在目标机器上执行
scp ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/file.sh ./
# 输入密码: ${FILE_JUMP_PASSWORD}
```

### 2. 手动登录流程

#### 2.1 交互式登录

```bash
ssh ${JUMP_USER}@${JUMP_HOST} -p ${JUMP_PORT}
# 输入密码: ${JUMP_PASSWORD}

# 在 JumpServer 提示符下
Opt> ${TARGET_HOST}

# 成功登录到目标机器
[${TARGET_USER}@${TARGET_HOST_FULL} ~]$
```

#### 2.2 在目标机器上的操作

```bash
# 切换到工作目录
cd ${TARGET_WORKDIR}

# 从文件传输跳板机下载文件
scp ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/test_script.sh ./
# 输入密码: ${FILE_JUMP_PASSWORD}

# 添加执行权限
chmod +x test_script.sh

# 运行测试
./test_script.sh
# 或者需要 sudo
sudo ./test_script.sh -c 50,51,52 -i 2

# 上传结果回文件传输跳板机
scp /tmp/test_results.txt ${FILE_JUMP_USER}@${FILE_JUMP_HOST}:${FILE_JUMP_DIR}/
# 输入密码: ${FILE_JUMP_PASSWORD}
```

### 3. 自动化登录和测试（使用 Expect）

#### 3.1 基础 Expect 脚本模板

创建文件 `jumpserver_login.expect`：

```expect
#!/usr/bin/expect -f

# 配置
set jump_host "jump.smartx.com"
set jump_port "2222"
set jump_user "chengcheng.luo"
set target_host "19.95"
set file_jump_host "192.168.17.20"
set file_jump_user "root"

# 从命令行参数或提示获取密码
if {$argc >= 1} {
    set jump_password [lindex $argv 0]
} else {
    stty -echo
    send_user "Enter jumpserver password: "
    expect_user -re "(.*)\n"
    set jump_password $expect_out(1,string)
    stty echo
    send_user "\n"
}

if {$argc >= 2} {
    set file_jump_password [lindex $argv 1]
} else {
    stty -echo
    send_user "Enter file transfer host password: "
    expect_user -re "(.*)\n"
    set file_jump_password $expect_out(1,string)
    stty echo
    send_user "\n"
}

set timeout 60
log_user 1

# 登录跳板机
spawn ssh ${jump_user}@${jump_host} -p ${jump_port}

expect {
    "password:" {
        send "${jump_password}\r"
    }
    timeout {
        puts "ERROR: Timeout waiting for password prompt"
        exit 1
    }
}

# 选择目标机器
expect {
    "Opt>" {
        send "${target_host}\r"
    }
    timeout {
        puts "ERROR: Timeout waiting for Opt> prompt"
        exit 1
    }
}

# 等待登录成功
expect {
    -re ".*smartx@.*" {
        puts "\n=== Successfully logged into target machine ==="
    }
    timeout {
        puts "ERROR: Timeout waiting for target machine prompt"
        exit 1
    }
}

sleep 2

# 切换到工作目录
send "cd /home/smartx/lcc\r"
expect -re ".*smartx@.*"

# 保持会话以便交互
interact
```

#### 3.2 自动化测试脚本模板

创建文件 `run_remote_test.expect`：

```expect
#!/usr/bin/expect -f

# 配置参数
set jump_host "jump.smartx.com"
set jump_port "2222"
set jump_user "chengcheng.luo"
set target_host "19.95"
set file_jump_host "192.168.17.20"
set file_jump_user "root"
set file_jump_dir "/root/lcc"
set target_workdir "/home/smartx/lcc"

# 从命令行参数获取密码
if {$argc < 2} {
    puts "Usage: $argv0 <jump_password> <file_jump_password> \[test_script\]"
    exit 1
}

set jump_password [lindex $argv 0]
set file_jump_password [lindex $argv 1]
set test_script [lindex $argv 2]
if {$test_script == ""} {
    set test_script "test_script.sh"
}

set timeout 120
log_user 1

# 登录到跳板机
spawn ssh ${jump_user}@${jump_host} -p ${jump_port}
expect "password:"
send "${jump_password}\r"

# 选择目标机器
expect "Opt>"
send "${target_host}\r"

# 等待登录成功
expect -re ".*smartx@.*"
sleep 2

# 切换工作目录
send "cd ${target_workdir}\r"
expect -re ".*smartx@.*"

# 下载测试脚本
puts "\n=== Downloading test script from file transfer host ==="
send "scp ${file_jump_user}@${file_jump_host}:${file_jump_dir}/${test_script} ./\r"
expect {
    "yes/no" {
        send "yes\r"
        exp_continue
    }
    "password:" {
        send "${file_jump_password}\r"
    }
    timeout {
        puts "ERROR: Timeout during scp"
        exit 1
    }
}
expect -re ".*smartx@.*"

# 添加执行权限
send "chmod +x ${test_script}\r"
expect -re ".*smartx@.*"

# 运行测试
puts "\n=== Running test script ==="
send "bash ${test_script} 2>&1 | tee /tmp/test_output.txt\r"

expect {
    -re ".*smartx@.*" {
        puts "\n=== Test completed ==="
    }
    timeout {
        puts "\n=== Test timeout ==="
        send "\003"
    }
}

sleep 2

# 上传结果
puts "\n=== Uploading results ==="
send "scp /tmp/test_output.txt ${file_jump_user}@${file_jump_host}:${file_jump_dir}/\r"
expect "password:"
send "${file_jump_password}\r"
expect -re ".*smartx@.*"

# 清理并退出
send "exit\r"
expect eof
```

#### 3.3 使用方式

**方式 1：交互式输入密码**

```bash
./jumpserver_login.expect
# 会提示输入两个密码
```

**方式 2：从环境变量读取**

```bash
# 设置环境变量（仅当前 session）
export JUMP_PASSWORD="your_jump_password"
export FILE_JUMP_PASSWORD="your_file_password"

# 创建包装脚本
cat > run_test.sh << 'EOF'
#!/bin/bash
read -sp "Enter jumpserver password: " JUMP_PASSWORD
echo
read -sp "Enter file transfer password: " FILE_JUMP_PASSWORD
echo

./run_remote_test.expect "$JUMP_PASSWORD" "$FILE_JUMP_PASSWORD" "$1"
EOF

chmod +x run_test.sh

# 使用
./run_test.sh test_script.sh
```

**方式 3：从文件读取（安全性较低，仅开发环境）**

```bash
# 创建密码文件（注意权限）
cat > .credentials << EOF
JUMP_PASSWORD=your_password_here
FILE_JUMP_PASSWORD=your_password_here
EOF

chmod 600 .credentials

# 在脚本中读取
source .credentials
./run_remote_test.expect "$JUMP_PASSWORD" "$FILE_JUMP_PASSWORD" test_script.sh
```

### 4. 完整测试流程示例

```bash
#!/bin/bash

# 1. 准备测试脚本
cat > /tmp/quick_test.sh << 'EOF'
#!/bin/bash
echo "Running quick test on $(hostname)"
echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"
echo "Bash version: $BASH_VERSION"
uname -a
EOF

# 2. 上传到文件传输跳板机
scp /tmp/quick_test.sh root@192.168.17.20:/root/lcc/

# 3. 读取密码
read -sp "Enter jumpserver password: " JUMP_PASS
echo
read -sp "Enter file transfer password: " FILE_PASS
echo

# 4. 创建并运行 expect 脚本
cat > /tmp/run_test.expect << EOF
#!/usr/bin/expect -f
set timeout 60
spawn ssh chengcheng.luo@jump.smartx.com -p 2222
expect "password:"
send "${JUMP_PASS}\r"
expect "Opt>"
send "19.95\r"
expect -re ".*smartx@.*"
sleep 2
send "cd /home/smartx/lcc\r"
expect -re ".*smartx@.*"
send "scp root@192.168.17.20:/root/lcc/quick_test.sh ./\r"
expect "password:"
send "${FILE_PASS}\r"
expect -re ".*smartx@.*"
send "chmod +x quick_test.sh\r"
expect -re ".*smartx@.*"
send "bash quick_test.sh\r"
expect -re ".*smartx@.*"
send "exit\r"
expect eof
EOF

chmod +x /tmp/run_test.expect
/tmp/run_test.expect

# 5. 清理
rm -f /tmp/run_test.expect
```

## 常见问题和技巧

### 1. Expect 脚本调试

```expect
# 开启详细日志
log_user 1

# 查看匹配的内容
exp_internal 1

# 增加超时时间
set timeout 300
```

### 2. 处理复杂的密码字符

如果密码包含特殊字符，使用单引号：

```bash
JUMP_PASSWORD='p@$$w0rd!#'
```

在 expect 中：

```expect
send "${jump_password}\r"
# 或使用转义
send "p@\$\$w0rd!#\r"
```

### 3. 多个命令批量执行

```expect
# 方法 1: 逐个发送
send "command1\r"
expect -re ".*prompt.*"
send "command2\r"
expect -re ".*prompt.*"

# 方法 2: 使用 here-doc
send "bash << 'SCRIPT_END'\r"
send "command1\r"
send "command2\r"
send "command3\r"
send "SCRIPT_END\r"
expect -re ".*prompt.*"
```

### 4. 捕获输出

```expect
# 捕获到变量
expect {
    -re "output: (.*)\n" {
        set captured $expect_out(1,string)
        puts "Captured: $captured"
    }
}

# 保存到文件
log_file /tmp/session.log
```

### 5. 错误处理

```expect
expect {
    "success" {
        puts "Operation succeeded"
    }
    "error" {
        puts "ERROR: Operation failed"
        exit 1
    }
    timeout {
        puts "ERROR: Operation timeout"
        exit 1
    }
    eof {
        puts "ERROR: Connection closed unexpectedly"
        exit 1
    }
}
```

## 安全注意事项

1. **密码管理**
   - ❌ 不要将密码硬编码在脚本中
   - ❌ 不要将密码提交到 git 仓库
   - ✅ 使用环境变量或运行时输入
   - ✅ 使用密码管理工具（如 pass、1Password CLI）

2. **文件权限**
   ```bash
   # Expect 脚本
   chmod 700 script.expect

   # 密码文件（如果必须使用）
   chmod 600 .credentials
   ```

3. **清理敏感信息**
   ```bash
   # 执行后清理
   unset JUMP_PASSWORD
   unset FILE_JUMP_PASSWORD

   # 清理日志中的敏感信息
   sed -i 's/password:.*/password: [REDACTED]/' logfile.txt
   ```

## 实际案例：CPU Monitor 调试

本次调试 cpu_monitor.sh 的完整流程：

### 步骤 1: 上传测试脚本

```bash
# 上传诊断脚本
scp /tmp/diagnose_bash_issue.sh root@192.168.17.20:/root/lcc/
scp /tmp/test_original_issue.sh root@192.168.17.20:/root/lcc/
scp /tmp/test_ps_performance.sh root@192.168.17.20:/root/lcc/

# 上传修复版本
scp ebpf-tools/cpu/cpu_monitor.sh root@192.168.17.20:/root/lcc/cpu_monitor_fixed.sh
```

### 步骤 2: 创建自动化测试脚本

```bash
cat > /tmp/test_cpu_monitor.expect << 'EOF'
#!/usr/bin/expect -f
# ... (参考前面的模板)
EOF
```

### 步骤 3: 执行测试

```bash
chmod +x /tmp/test_cpu_monitor.expect
/tmp/test_cpu_monitor.expect
```

### 步骤 4: 收集结果

```bash
# 结果自动上传回文件传输跳板机
# 然后从本地下载
scp root@192.168.17.20:/root/lcc/test_results.txt ./
```

## 附录：完整示例脚本

参见 `examples/` 目录下的示例脚本：
- `jumpserver_login.expect` - 基础登录脚本
- `run_remote_test.expect` - 自动化测试脚本
- `batch_upload.sh` - 批量上传文件
- `batch_download.sh` - 批量下载结果

## 参考资料

- [Expect 官方文档](https://core.tcl-lang.org/expect/index)
- [SSH JumpHost 配置](https://www.redhat.com/sysadmin/ssh-proxy-bastion-proxyjump)
- [Expect 实战示例](https://likegeeks.com/expect-command/)
