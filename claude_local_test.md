
# Testing

## Test Environment
程序需要进行测试的环境为为两类：1. 虚拟化 host ； 2. 虚拟化 guest 。
无论那种环境，如果存在 python-bcc，则测试运行时应当使用 sudo python2 <program>, 存在 python3-bpfcc 则使用 sudo python3 <program>

###  program should running on virtualization host: 
BCC tools requiring testing should be deployed to: `smartx@192.168.70.33:/home/smartx/lcc/`
- Create test subdirectories named after the tool's purpose for each testing session
- Use `ssh mcpserver` or direct `scp` for deployment
- Execute tests using `ssh mcpserver` or direct `ssh` connections

### program should running in virtualization guest:
- 测试 vm 为：root@192.168.29.151:/root/lcc, 需要在 vm 中运行的代码在该 vm 中测试。
- 使用 ssh && scp 工具，或者使用相应 mcp server  