
# Testing

## Test Environment

###  program should running on virtualization host: 
BCC tools requiring testing should be deployed to: `smartx@192.168.70.33:/home/smartx/lcc/`
- Create test subdirectories named after the tool's purpose for each testing session
- Use `ssh mcpserver` or direct `scp` for deployment
- Execute tests using `ssh mcpserver` or direct `ssh` connections

### program should running in virtualization guest:
- 测试 vm 为：root@192.168.29.151:/root/lcc, 需要在 vm 中运行的代码在该 vm 中测试。
- 使用 ssh && scp 工具，或者使用相应 mcp server  