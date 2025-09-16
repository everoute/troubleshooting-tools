
1. 测试环境
主机： smartx@172.21.152.82 
ssh 免密登录。   
首先 scp 需要用的代码以及相关工具到目标主机 /home/smartx/lcc 目录下: 
a. 需要 copy 到远端的代码目录：
ebpf-tools/performance/system-network  && ebpf-tools/performance/vm-network 
 

代码目录：系统网络，虚拟机网络分别在

 2. 测试参数

 系统网络三个工具需要测试的参数分别是：
 sudo python3 system_network_perfomance_metrics.py --internal-interface <internal-port-name> --phy-interface <physical-port-name> --src-ip <sip> --dst-ip <dip> --direction rx/tx --protocol <protocol> 
 sudo python3 system_network_latency_details.py --phy-interface <physical-port-name> --src-ip <sip> --dst-ip <dip> --direction rx/tx --protocol <protocol>
 sudo python3 system_network_icmp_rtt.py --src-ip <sip> --dst-ip <dip> --direction rx/tx --phy-iface1 <physical-port-name> 

 10.132.114.11 为本地 IP， 10.132.114.12 为远端 IP 。 
 physical-port-name 为 ens11。
 internal-port-name 为 port-storage。

 direction 为 rx 时， src-ip 为远端 ip, dst-ip 为本地 IP； direction 为 tx 时相反。  
 前两个系统网络工具 protocol 分别使用 tcp && udp 测试(不支持 icmp）。 
 第三个工具仅支持 icmp, 无须 protocol 参数。 


虚拟机网络三个工具需要测试的分别是：
sudo python3 vm_network_latency_summary.py --vm-interface <vnet-port-name> --phy-interface <physical-port-name> --direction rx/tx --src-ip <sip> --dst-ip <dip> --protocol <protocol> 
sudo python3 vm_network_latency_details.py --vm-interface <vnet-port-name> --phy-interface <physical-port-name> --direction rx/tx --src-ip <sip> --dst-ip <dip> --protocol <protocol> 
sudo python3 vm_network_performance_metrics.py --vm-interface <vnet-port-name> --phy-interface <physical-port-name> --direction rx/tx --src-ip <sip>  --dst-ip <dip>  --protocol <protocol>

172.21.153.114 为本地 IP， 172.21.153.113 为远端 IP 。 
vnet-port-name 为 vnet0。
physical-port-name 为 ens4。 

direction 为 rx 时， src-ip 为本地 ip, dst-ip 为远端 IP； direction 为 tx 时相反。  
protocol 分别选择 tcp && udp && icmp 
 

3. 测试流程


a. 需要测试以上两个文件夹中的 6 个工具, 首先根据说明生成所有需要测试的用例对应的完整命令:
系统网络的前两个工具前两个需要分别测试 rx && tx 下的 tcp && udp, 需要使用的数据见 2;
系统网络的第三个工具前两个需要分别测试 rx && tx,  需要使用的数据见 2;

虚拟机网络三个工具都需要测试 tcp rx && tx 方向, 以及 tcp && udp && icmp, 详见 2。 

记录需要执行的所有用例到临时文件 test/performance-test-cases.txt 

b. 使用 @test/run_all_tests.py  工具进行完整测试。  
c. 代码基本都有调试信息， ctrl+c 结束后会输出调试信息,也包含在结果文件中.
d. 记录每个测试的结果到测试 case 结果汇总文件夹(与 spec 文件前缀相同，如 performance-test- ,后缀为 results），其中每个测试的结果一个结果文件，文件都以测试 case 程序名称 + case
 本身特征（例如方向 + 协议 等）命名，后缀一个是 result。 

测试所有用例完成后，生成一个测试用例的结果汇总文件夹,包含每个测试用例对应的输出结果文件，包含完整测试用例输出。 根据每个用例的结果可以总结一个汇总结果。




