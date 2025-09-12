
1. 测试环境
主机： smartx@172.21.152.82 , ssh 免密登录。   
代码目录：系统网络，虚拟机网络分别在
 /home/smartx/ebpf-tools/performance/system-network  && /home/smartx/ebpf-tools/performance/vm-network 

 2. 测试参数

 系统网络三个工具需要测试的参数分别是：
 sudo python3 system_network_perfomance_metrics.py --internal-interface <internal-port-name> --phy-interface <physical-port-name> --src-ip <sip> --dst-ip <dip> --direction rx/tx --protocol tcp
 sudo python3 system_network_latency_details.py --phy-interface <physical-port-name> --src-ip <sip> --dst-ip <dip> --direction rx/tx --protocol tcp
 sudo python3 system_network_icmp_rtt.py --src-ip <sip> --dst-ip <dip> --direction rx/tx --phy-iface1 <physical-port-name> 

 10.132.114.11 为本地 IP， 10.132.114.12 为远端 IP 。 direction 为 rx 时， src-ip 为远端 ip, dst-ip 为本地 IP； direction 为 tx 时相反。  
 前两个 protocol 分别选 tcp /icmp 测试。 
 physical-port-name 为 ens4。
 internal-port-name 为 port-storage。


虚拟机网络三个工具需要测试的分别是：
sudo python3 vm_network_latency_summary.py --vm-interface <vnet-port-name> --phy-interface <physical-port-name> --direction rx/tx --src-ip <sip> --dst-ip <dip> --protocol tcp
sudo python3 vm_network_latency_details.py --vm-interface <vnet-port-name> --phy-interface <physical-port-name> --direction rx/tx --src-ip <sip> --dst-ip <dip> --protocol tcp
sudo python3 vm_network_performance_metrics.py --vm-interface <vnet-port-name> --phy-interface <physical-port-name> --direction rx/tx --src-ip <sip>  --dst-ip <dip>  --protocol tcp

  172.21.153.114 为本地 IP， 172.21.153.113 为远端 IP ; direction 为 rx 时， src-ip 为本地 ip, dst-ip 为远端 IP； direction 为 tx 时相反。  
  vnet-port-name 为 vnet0。
  physical-port-name 为 ens4。 
 

 3. 测试流程

a. 需要测试以上两个文件夹中的 6 个工具, 首先根据说明生成所有需要测试的用例对应的完整命令:
系统网络的前两个工具前两个需要分别测试 rx && tx 下的 tcp && icmp, 需要使用的数据见 2;
系统网络的第三个工具前两个需要分别测试 rx && tx,  需要使用的数据见 2;

虚拟机网络三个工具都需要测试 tcp rx && tx 方向的情况。 

b. 记录需要的所有用例到临时文件;
c. 使用 test/tools/bpf_remote_executor.py 执行远端测试，逐个开始测试，并记录每个测试的结果到测试结果文件。 注意每个测试的总时长不能太短，记录没有输出任何结果的情况。 




