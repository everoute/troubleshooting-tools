# 使用方式：
## 1. 构建 vm_pair.txt 文件，格式如下：
cat vm_pair.txt
18fe6add-24a3-46de-9a2e-a6a979185342 2fa052f5-ea08-43ce-9684-95ee8d500eb5
36ce5a8d-d7af-4d1a-8376-21132454003a cd534fb6-eccf-48aa-8789-b189f18c5b46
5448eaf5-1884-483f-809f-eccd51279741 b3bfcf12-a88f-4db0-8ffd-c19bc89156dc

其中每一行表示一个 vm pair(两个 vm uuid，通过空格分割，vm uuid 通过 tower 虚拟机详情页获取): 即划分到同一组的一个 windows vm 和 一个 linux vm.
需要将需要为其分配 cpu 的所有 vm 对的 uuid 写入 vm_pair.txt 文件中.

## 2. 自动为输入的 vm 对规划 cpu 分配
为 vm_pair.txt 文件中列出的每个 vm 对自动规划 cpu 分配, 并输出规划结果. 接着可选是否执行上述 vm cpu 规划结果，配置每组 vm 对中的 vm：
sudo ./set-vm-pair-cpu-affinity.sh vm_pairs.txt 

## 3. 输出结果示例
[root@shangfei-poc1 15:30:39 lcc]$ sudo ./set-vm-pair-cpu-affinity.sh vm_pairs.txt                                                                                                                                                            
machine.slice configured CPUs: 0,7,9,11-48,50-95  (Total: 87)                                                                                                                                                                                 
Number of VM pairs to process: 9                                                                                                                                                                                                              
NUMA node 0 available CPUs: 0 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40 42 44 46 48 50 52 54 56 58 60 62 64 66 68 70 72 74 76 78 80 82 84 86 88 90 92 94                                                                                   
NUMA node 1 available CPUs: 7 9 11 13 15 17 19 21 23 25 27 29 31 33 35 37 39 41 43 45 47 51 53 55 57 59 61 63 65 67 69 71 73 75 77 79 81 83 85 87 89 91 93 95                                                                                 
                                                                                                                                                                                                                                              
Starting CPU allocation for each VM pair...                                                                                                                                                                                                   
                                                                                                                                                                                                                                              
------------------------------------------------------                                                                                                                                                                                        
VM Pair: 18fe6add-24a3-46de-9a2e-a6a979185342 and 2fa052f5-ea08-43ce-9684-95ee8d500eb5                                                                                                                                                        
Separate allocation: vm 18fe6add-24a3-46de-9a2e-a6a979185342 from NUMA node 0, vm 2fa052f5-ea08-43ce-9684-95ee8d500eb5 from NUMA node 0                                                                                                       
  18fe6add-24a3-46de-9a2e-a6a979185342 allocated CPUs: 0 12 14 16                                                                                                                                                                             
  2fa052f5-ea08-43ce-9684-95ee8d500eb5 allocated CPUs: 18 20 22 24                                                                                                                                                                            
------------------------------------------------------                                                                                                                                                                                        
VM Pair: 36ce5a8d-d7af-4d1a-8376-21132454003a and cd534fb6-eccf-48aa-8789-b189f18c5b46                                                                                                                                                        
Separate allocation: vm 36ce5a8d-d7af-4d1a-8376-21132454003a from NUMA node 0, vm cd534fb6-eccf-48aa-8789-b189f18c5b46 from NUMA node 0                                                                                                       
  36ce5a8d-d7af-4d1a-8376-21132454003a allocated CPUs: 26 28 30 32                                                                                                                                                                            
  cd534fb6-eccf-48aa-8789-b189f18c5b46 allocated CPUs: 34 36 38 40                                                                                                                                                                            
------------------------------------------------------                                                                                                                                                                                        
VM Pair: 5448eaf5-1884-483f-809f-eccd51279741 and b3bfcf12-a88f-4db0-8ffd-c19bc89156dc                                                                                                                                                        
Separate allocation: vm 5448eaf5-1884-483f-809f-eccd51279741 from NUMA node 0, vm b3bfcf12-a88f-4db0-8ffd-c19bc89156dc from NUMA node 0                                                                                                       
  5448eaf5-1884-483f-809f-eccd51279741 allocated CPUs: 42 44 46 48                                                                                                                                                                            
  b3bfcf12-a88f-4db0-8ffd-c19bc89156dc allocated CPUs: 50 52 54 56                                                                                                                                                                            
------------------------------------------------------                                                                                                                                                                                        
VM Pair: 9141b36f-708c-4e4f-8345-8a84e056711d and c72d882b-7c2d-4317-b608-7d6794e84010                                                                                                                                                        
Separate allocation: vm 9141b36f-708c-4e4f-8345-8a84e056711d from NUMA node 0, vm c72d882b-7c2d-4317-b608-7d6794e84010 from NUMA node 0                                                                                                       
  9141b36f-708c-4e4f-8345-8a84e056711d allocated CPUs: 58 60 62 64                                                                                                                                                                            
  c72d882b-7c2d-4317-b608-7d6794e84010 allocated CPUs: 66 68 70 72                                                                                                                                                                            
------------------------------------------------------                                                                                                                                                                                        
VM Pair: 20d72521-6786-4694-a7a4-6176454a6236 and dbaa73a4-ba54-41cf-93e5-5c4a10973f22                                                                                                                                                        
Separate allocation: vm 20d72521-6786-4694-a7a4-6176454a6236 from NUMA node 0, vm dbaa73a4-ba54-41cf-93e5-5c4a10973f22 from NUMA node 0                                                                                                       
  20d72521-6786-4694-a7a4-6176454a6236 allocated CPUs: 74 76 78 80                                                                                                                                                                            
  dbaa73a4-ba54-41cf-93e5-5c4a10973f22 allocated CPUs: 82 84 86 88                                                                                                                                                                            
------------------------------------------------------                                         
  Thread groups:
    Group 42: CPU 90
    Group 44: CPU 92
    Group 46: CPU 94
NUMA node 1:
  CPUs: 73 75 77 79 81 83 85 87 89 91 93 95
  Thread groups:
    Group 25: CPU 73
    Group 27: CPU 75
    Group 29: CPU 77
    Group 31: CPU 79
    Group 33: CPU 81
    Group 35: CPU 83
    Group 37: CPU 85
    Group 39: CPU 87
    Group 41: CPU 89
    Group 43: CPU 91
    Group 45: CPU 93
    Group 47: CPU 95
------------------------------------------------------
CPU allocation plan complete.

Do you want to proceed with CPU binding operations? (y/n): 
### 到上面这一步，则完成规划，输入 y 然后 enter，则执行上述 vm cpu 规划结果，配置每组 vm 对中的 vm，知道执行结束，完成配置。


# 注意事项
1. 此种配置方式配置的 vm cpu binding， 如果在界面上做任何同集群 vm 编辑操作，配置将失效。因此在配置好后运行程序时，需要确保界面上没有对 vm 进行任何编辑操作。
2. 默认情况仅做 vm vcpu binding，预留 machine-slice 若干个 cpu 给 vhost
3. 输入的 vm 对过多，预留给 vhost 的 cpu 过少则报错。
