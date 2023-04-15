###### tags: `tryhackme`

[TOC]

# Linux 提权

## 一. 前言

本篇文章主要总结了一下linux中常见的提权技巧。如有错误，敬请指正。

## 二. 简介

提权是一场没有银弹的旅程，是否能提权成功完成取决了目标系统的配置，比如内核版本、已安装的应用程序、支持的编程语言以及用户的密码。这些都是我们可以提权到管理员权限的关键要素。

本篇文章主要涵盖一些主要的提权手法，希望能让您对提权过程有一个更好的理解。


## 三. 什么是提权？

### 3.1 提权意味着什么？

顾名思义，提权通常涉及到从一个低权限的账户到一个高权限的账户。用更技术的话来说，提权指的是利用操作系统或应用程序的漏洞、设计缺陷或配置疏忽等弱点对某些资源进行未授权访问。



### 3.2 为什么提权很重要？

在实际的渗透过程中，很少可以直接拿到一个具有管理员权限的 shell。而提权能让我们获得管理员级别的访问权限，所以提权是渗透过程中

提权允许你进行以下操作：

- 重置密码
- 绕过访问控制并损害受保护的数据
- 编辑软件配置
- 权限维持 Enabling persistence
- 改变已存在的用户的权限
- 执行任意需管理员权限的命令

### 3.3 枚举主机信息

一旦你已获得系统的访问权限，那么枚举就是你应该做的第一件事。渗透测试不像CTF，CTF在获取系统的访问权限后一般就可以停下了。
正如你将看到的，枚举在后渗透阶段和之前一样重要。

#### 1. hostname 命令

`hostname` 命令将会返回目标主机的主机名。尽管该值可被轻易改变或是含有一个相对无意义的字符串（比如 Ubuntu-3487340239）。但在某些情况下，`hostname` 命令可提供目标系统在组织网络内所充当的角色信息。（比如 SQL-PROD-01 表明这是一台 SQL 服务器）

#### 2. uname -a 命令

该命令将会打印系统信息，显示有关系统内核的额外细节。当我们寻找潜在的内核提权漏洞时，该信息特别有用。

#### 3. /proc/version 文件

proc 文件系统(procfs) 提供有关目标系统进程的信息。你可在许多不同的 Linux 发行版中找到 proc，这使得其成为你的武器库中的一个重要工具。

 `/proc/version` 会显示内核版本信息以及一些额外的数据。比如是否安装了编译器（例如 GCC）

#### 4. /etc/issue 文件

通过查看 `/etc/issue` 文件可以确定系统类型。这个文件通常包含一些关于操作系统的信息，但是可以被轻易地改变或定制。所有包含系统信息的文件都可被定制化或改变，所以为了对系统有一个更好的理解，最好是把所有相关的文件都查看一下。

#### 5. ps 命令

在 Linux 系统上，`ps` 命令是一个查看运行中的进程的一个高效方式。

`ps`（Process Status） 的输出将会显示以下信息：
- PID：进程 ID（对进程来说是唯一的）
- TTY：用户所用的终端类型
- Time：进程使用的 CPU 时间数（这不是进程已运行的时间）
- CMD：正在运行的命令或可执行文件（将不会展示任意的命令行参数）

`ps` 命令提供了一些有用的选项：
- ps-A：查看所有运行着的进程
- ps axjf：查看进程树，如下图：

![](https://i.imgur.com/gzmcqTg.png)

- ps aux：

#### env 命令

`env` 命令将显示环境变量。

![](https://i.imgur.com/eGrJOFn.png)

PATH 变量可能具有编译器或脚本语言（例如 Python）的路径，可用于在目标系统上运行代码或提权。

#### sudo -l

目标系统可以配置为允许用户以 root 权限运行一些（或所有）命令。 而 `sudo -l` 命令就用于列出您可用 `sudo` 运行（即以 root 权限运行）的所有命令。

#### ls

Linux 中常用的命令之一可能是 `ls`。

在寻找潜在的特权升级向量时，请记住始终使用带有 `-la` 参数的 `ls` 命令。下面的示例显示了使用 ls 或 `ls -l` 命令时遗漏了 “secret.txt” 文件的情况。

> a 选项显示所有文件



![](https://i.imgur.com/2KaaBLT.png)

#### id 命令

`id` 命令将提供用户权限级别和组成员身份的总体概览。 值得记住的是，`id` 命令也可 用于获取另一个用户的相关信息，如下所示。

![](https://i.imgur.com/5MJJZK2.png)

#### /etc/passwd 文件

读取 `/etc/passwd` 文件是发现系统用户的一种简单方法。

![](https://i.imgur.com/QsYnLCs.png)

虽然输出可能很长而且有点吓人，但它可以很容易地被剪切并转换成一个有用的列表以用于暴力攻击。

![](https://i.imgur.com/W4Knz1t.png)

请记住，这将返回所有用户，其中有一些不是很有用的系统或服务用户。

另一种方法可能是在 /etc/passwd 文件里查找 “home” ，因为真实用户很可能将他们的文件夹放在 “home” 目录下。

![](https://i.imgur.com/ECddRM6.png)

#### history

使用 `history` 命令查看较早的命令可以让我们对目标系统有一些了解。尽管很少发生，但之前的命令可能存储了密码或用户名等信息。

#### ifconfig

目标系统可能是另一个网络的枢轴点。 `ifconfig` 命令将为我们提供有关系统网络接口的信息。下面的示例显示目标系统具有三个接口（eth0、tun0 和 tun1）。我们的攻击机器可以到达 eth0 接口，但不能直接访问其他两个网络。

![](https://i.imgur.com/WqpJcMZ.png)

这可以使用 `ip route` 命令确认，以查看存在哪些网络路由。

![](https://i.imgur.com/teDg35x.png)


#### netstat

在对现有接口和网络路由进行初步检查后，可以尝试查看现有通信。 `netstat` 命令可以与几个不同的选项一起使用，以收集有关现有连接的信息。
- `netstat -a`：显示所有侦听端口和已建立的连接。
- `netstat -at` 或 `netstat -au` 可分别列出 TCP 或 UDP 协议的连接
- `netstat -l`：列出处于 “侦听” 模式的端口。这些端口已打开并准备好接受传入连接。这可以与 “t” 选项一起使用，以仅列出使用 TCP 协议侦听的端口（如下）

![](https://i.imgur.com/iO4je25.png)

- `netstat -s`：按协议列出网络使用的统计信息（如下）这也可以与 `-t` 或 `-u` 选项一起使用，以将输出限制为特定协议。

![](https://i.imgur.com/zA8luIS.png)

- `netstat -tp`：列出带有服务名称和 PID 信息的连接。

![](https://i.imgur.com/1iWjl59.png)

这也可以与 `-l` 选项一起使用以列出监听端口（如下）

![](https://i.imgur.com/p8T119D.png)

我们可以看到 “PID/Program name” 列是空的，因为这个进程属于另一个用户。 使用 root 权限再运行该命令一次，可以看到此信息显示为 2641/nc (netcat)

![](https://i.imgur.com/YlKvanS.png)

- `netstat -i`：显示接口统计信息。我们在下面看到 “eth0” 和 “tun0” 比 “tun1” 更活跃。


![](https://i.imgur.com/qdHbOyu.png)

您在博客文章、文章和课程中最常看到的 `netstat` 用法是 `netstat -ano`，它可以细分如下：
- -a：显示所有套接字
- -n：不解析主机名
- -o：显示计时器

![](https://i.imgur.com/gpd4Ub8.png)


#### find 命令

有时在目标系统中搜索重要信息和潜在的特权升级向量可能会很有成效。而内置的 “find” 命令很有用，值得保留在您的武器库中。 以下是 “find” 命令的一些有用示例。

**查找文件：**
- `find . -name flag1.txt`：在当前目录下查找名为 "flag1.txt" 的文件。
- `find /home -name flag1.txt`：在 /home 目录下查找名为 "flag1.txt" 的文件
- `find / -type d -name config`：在 / 目录下查找名为 config 的目录
- `find / -type f -perm 0777`：在根目录下查找具有 777 权限的文件（777 表示所有用户可读、可写、可执行）
- `find / -perm a=x`：在根目录下查找可执行文件
- `find /home -user frank`：在 /home 目录下查找用户 ”frank“ 的所有文件
- `find / -mtime 10`：在根目录下查找最近十天内修改过的文件
- `find / -atime 10`：在根目录下查找最近十天内访问过的文件。
- `find / -cmin -60`：在根目录下查找在最近一小时内改变过的文件（60 分钟）
- `find / -amin -60`：在根目录下查找在最近一小时内访问过的文件（60 分钟）
- `find / -size 50M`：在根目录下查找大小为 50MB 的文件。此命令还可以与 (+) 和 (-) 符号一起使用，以指定大于或小于给定大小的文件。

![](https://i.imgur.com/HoMc2Ij.png)

上面的示例返回大于 100 MB 的文件。

注意：

“find” 命令往往会产生错误，所以有时输出可能难以阅读。明智的做法是使用带有 “`-type f 2>/dev/null`” 选项的 “find” 命令将错误重定向到 “/dev/null” 并获得更清晰的输出（如下）。

![](https://i.imgur.com/t19UFTW.png)


以下三个命令在根目录下查找可写的文件夹：
- `find / -writable -type d 2>/dev/null`
- `find / -perm -222 -type d 2>/dev/null`
- `find / -perm -o w -type d 2>/dev/null`

上述三个可能导致相同结果的不同 “find” 命令的原因可在手册文档中看到。正如您在下面看到的，perm 参数会影响 “find” 命令的工作方式。

![](https://i.imgur.com/514OZ1V.png)

以下命令在根目录下查找可以执行的目录：
```bash
find / -perm -o x -type d 2>/dev/null
```

以下命令在根目录下查找开发工具和支持的编程语言：
- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`


**查找具有特定权限的文件**

下面是一个简短的示例，用于查找设置了 SUID 位的文件。 SUID 位允许文件以拥有它的帐户的特权级别运行，而不是运行它的帐户，这导致了一个有趣的提权手法。
- `find / -perm -u=s -type f 2>/dev/null`：在根目录下查找带有 SUID 位的文件，这允许我们以比当前用户更高的权限级别运行该文件。



```bash
find / -writable -type d 2>/dev/null
```

## 四. 内核漏洞利用提权

理想情况下，权限升级会导致 root 权限。这有时可以简单地通过利用现有漏洞来实现，或者在某些情况下通过访问具有更多权限、信息或访问权限的另一个用户帐户来实现。 除非单个漏洞导致 root shell，否则权限升级过程将依赖于错误配置和松散的权限。 Linux 系统上的内核管理组件之间的通信，例如系统上的内存和应用程序。这个关键功能需要内核有特定的权限；因此，成功的利用可能会导致 root 权限

内核利用方法很简单； 
1. 识别内核版本 
2. 搜索并找到目标系统内核版本的漏洞利用代码
3. 运行漏洞利用脚本 

虽然看起来很简单，但请记住，内核漏洞利用失败可能会导致系统崩溃。在尝试内核利用之前，请确保这种潜在结果在您的渗透测试范围内是可以接受的。

**研究来源：** 
根据您的发现，您可以使用 Google 搜索现有的漏洞利用代码。 https://www.linuxkernelcves.com/cves 等来源也很有用。 另一种选择是使用像 LES (Linux Exploit Suggester) 这样的脚本，但请记住，这些工具可能会产生误报（报告不影响目标系统的内核漏洞）或漏报（不报告任何内核漏洞，尽管内核是易受伤害的）。 

**提示/注意事项：** 
在 Google、Exploit-db 或 searchsploit 上搜索漏洞时，对内核版本过于具体 在启动之前，请务必了解漏洞利用代码的工作原理。一些漏洞利用代码可以对操作系统进行更改，使它们在进一步使用时不安全，或者对系统进行不可逆的更改，从而在以后产生问题。当然，在实验室或 CTF 环境中，这些可能不是什么大问题，但在真正的渗透测试过程中，这些绝对不能。 一些漏洞利用在运行后可能需要进一步的交互。阅读漏洞利用代码提供的所有注释和说明。 您可以分别使用 SimpleHTTPServer Python 模块和 wget 将漏洞利用代码从您的机器传输到目标系统。

## 五. 提权：Sudo

sudo 命令默认允许你以 root 权限运行一个程序。在一些情况下，系统管理员可能需要为普通用户提供一些灵活的权限。

举个例子，初级 SOC 分析师可能需要定期使用 Nmap，并且可能需要运行一些需要 root 权限的命令，比如 Nmap 的 TCP SYN 扫描。在这种情况下，系统管理员可以允许该用户仅以 root 权限运行 Nmap，同时在系统的其余部分保持其常规权限级别。

任何用户都可以使用 `sudo -l` 命令查看其当前与 root 权限相关的情况。

https://gtfobins.github.io/ 是一个有价值的资源，它提供了针对具有 sudo 权限程序的相关利用方式。例如 namp 具有 sudo 权限时，如何通过其得到一个 root shell。


### 1. 利用应用程序功能

有些应用程序运行时是以 sudo 权限运行的，如果该应用程序具有一些能读取或加载文件的选项，若该文件的内容我们可控，那么我们就可以利用这个选项来进行一些提权操作。


例如以下的 Apache2 应用。Apache2 有一个选项支持加载备用配置文件（`-f`：指定备用 ServerConfigFile）。

![](https://i.imgur.com/eZcZfsW.png)

使用此选项加载 `/etc/shadow` 文件将导致包含 /etc/shadow 文件第一行的错误消息。

### 2. 利用 LD_PRELOAD

在某些系统上，您可能会看到 LD_PRELOAD 环境选项。

![](https://i.imgur.com/MmjqURa.png)

LD_PRELOAD 是一个允许任何程序使用共享库的函数。这篇[文章](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/)将让您了解 LD_PRELOAD 的功能。如果启用 “env_keep” 选项，那么我们可以生成一个共享库，它将在程序运行之前加载和执行。请注意，如果真实用户 ID 与有效用户 ID 不同，LD_PRELOAD 选项将被忽略。

这个特权升级向量的步骤可以总结如下:
1. 检查 LD_PRELOAD（使用 env_keep 选项）
2. 编写并编译共享对象文件（.so 扩展名）的简单 C 代码
3. 使用 sudo 权限和指向我们的 .so 文件的 LD_PRELOAD 选项运行程序

以下 C 代码将简单地生成一个 root shell：
```cpp
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

我们可以将此代码保存为 shell.c，并使用以下参数使用 gcc 将其编译为共享对象文件；

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```
![](https://i.imgur.com/lRjTXOd.png)

当我们运行具有 sudo 权限的任意程序时，我们就可以使用以上的共享对象文件。在我们的例子中，可以使用 Apache2、find 或任何我们可以使用 sudo 运行的程序。

**回答以下问题：**
- 用户 “karen” 可在目标系统上执行多少个具有sudo 权限的程序？
- 如果您的用户对 nmap 具有 sudo 权限，您将如何使用 Nmap 生成 root shell？
- frank 密码的哈希值是多少？（用sudo -l 看到的 nano 去读 /etc/shadow）


## 六. 提权：SUID

许多 Linux 的权限控制依赖于控制用户和文件的交互，这是通过权限完成的。我们知道文件可以具有读取、写入和执行权限。Linux 根据用户的权限级别分配文件权限。然而 SUID（Set-user Identification）和 SGID（Set-group Identification）不同，这两项标识允许用户分别以文件所有者和文件组所有者的权限级别来执行文件。

您会注意到这些文件设置了一个 “s” 位来显示它们的特殊权限级别。

`find / -type f -perm -04000 -ls 2>/dev/null` 将列出设置了 SUID 或 SGID 位的文件。

![](https://i.imgur.com/zcWSSN0.png)

一个好的做法是将此列表中的设置了 suid 或 sgid 标识的可执行文件与 GTFOBins (https://gtfobins.github.io) 进行比较。

上面的列表显示 nano 设置了 SUID 位。不幸的是，GTFObins 并不能帮我们马上提权。在实际的提权场景中，我们需要找到中间步骤来帮助我们利用我们所拥有的任何微小发现。

![](https://i.imgur.com/gnTa9tK.png)

为 nano 文本编辑器设置的 SUID 位允许我们使用文件所有者的权限创建、编辑和读取文件。 Nano 由 root 拥有，这可能意味着我们可以以比当前用户更高的权限级别来读取和编辑文件。在这个阶段，我们有两个基本的提权方法：
1. 读取 `/etc/shadow` 文件
2. 将我们的用户添加到 `/etc/passwd`。


以下是使用这两种方法的简单步骤。

1. 运行 `find / -type f -perm -04000 -ls 2>/dev/null` 命令发现 nano 文本编辑器设置了 SUID 比特位。
2. 使用 `nano /etc/shadow` 命令显示 `/etc/shadow` 文件的内容。得到了该文件的内容后，我们就可以用 unshadow 工具创建一个可被 John the Ripper 破解的文件。为此，unshadow 需要 `/etc/shadow` 和 `/etc/passwd` 文件。

![](https://i.imgur.com/yTMffvw.png)

unshadow 工具的用法如下所示:

```bash
unshadow passwd.txt shadow.txt > passwords.txt
```

![](https://i.imgur.com/WO1iHXE.png)

有了正确的单词表和一点运气， John the Ripper 可以以明文形式返回一个或多个密码。有关 John the Ripper 的更详细的房间，您可以访问 https://tryhackme.com/room/johntheripper0

另一种选择是添加一个具有 root 权限的新用户。这将帮助我们规避繁琐的密码破解过程。下面是一个简单的方法来做到这一点：

我们需要新建用户的密码哈希值。这可以使用 Kali Linux 上的 openssl 工具快速完成。 

![](https://i.imgur.com/MCZkRp4.png)

然后，我们会将此密码和用户名添加到 `/etc/passwd` 文件中。

![](https://i.imgur.com/g1dHAD2.png)

添加用户后（请注意如何使用 root:/bin/bash 提供 root shell）我们将需要切换到该用户并希望拥有 root 权限。

![](https://i.imgur.com/LB9NTdG.png)

## Capabilities 提权

系统管理员可以用来提高进程或二进制文件权限级别的另一种方法是 “Capabilities”（功能） 。Capabilities 有助于在更精细的级别管理权限。
例如，如果 SOC 分析师需要使用需要发起套接字连接的工具，而普通用户将无法做到这一点。如果系统管理员不想给这个用户更高的权限，他们可以更改二进制文件的功能。因此，二进制文件无需更高权限的用户即可完成任务。

capabilities 手册页提供了有关其用法和选项的详细信息。

我们可以使用 `getcap` 工具列出启用的 capabilities。

![](https://i.imgur.com/yhcR76Z.png)

当以非特权用户身份运行时，`getcap -r /` 会产生大量错误，因此最好将错误消息重定向到 /dev/null。

请注意，vim 及其副本都没有设置 SUID 位。因此，在枚举查找 SUID 的文件时，无法发现此特权升级向量。

![](https://i.imgur.com/qBhUfDi.png)

GTFObins 有一个很好的二进制文件列表，如果我们发现任何设置的 capabilities，可以利用这些二进制文件进行提权。 我们注意到 vim 可以与以下命令和 payload 一起使用：

![](https://i.imgur.com/o2vFRFm.png)

这将启动一个 root shell，如下所示；

![](https://i.imgur.com/oHnwfki.png)

**回答下列问题：**

1. 有多少二进制文件设置了 capabilities？

使用 `getcap -r / 2>/dev/null` 命令即可

3. flag4.txt 文件的内容是什么？

用 vim 或 view 的功能提权都可以。记得把 py 换成 py3

![](https://i.imgur.com/gwPIl2U.png)


## 提权：定时任务

Cron job 定时任务用于在特定时间运行脚本或二进制文件。默认情况下，它们以其所有者而非当前用户的权限运行。虽然正确配置的定时任务本身并不容易受到攻击，但它们可以在某些情况下提供特权升级向量。

这个想法很简单：如果有一个以 root 权限运行的计划任务，并且我们可以更改将要运行的脚本，那么我们的脚本将以 root 权限运行。


定时任务配置被存储为 crontabs(crons tables)，以查看该任务下次将会被运行的时间和日期。

系统上的每个用户都有他们的 crontab 文件，并且无论他们是否登录都可以运行特定的任务。如您所料，我们的目标是找到一个由 root 设置的定时任务并让它运行我们的脚本，最好是一个反弹 shell 的脚本。

任何用户都可在 `/etc/crontab` 目录下读取系统内的定时任务文件。

虽然 CTF 机器可以让定时任务每分钟或每 5 分钟运行一次，但在渗透测试活动中，您会更频繁地看到每天、每周或每月运行的任务。

![](https://i.imgur.com/QutPTQB.png)

您可以看到 `backup.sh` 脚本被配置为每分钟运行一次。该文件的内容显示了一个创建 prices.xls 文件备份的简单脚本。

![](https://i.imgur.com/FRaztWL.png)

由于我们当前的用户可以访问这个脚本，我们可以很容易地修改它来创建一个反向 shell 并希望具有 root 权限。

但有两个点需要注意：
1. 命令语法会因可用工具而异。 （例如 `nc` 可能不支持您在其他情况下使用过的 -e 选项）

2. 我们应该总是更喜欢启动反向 shell，因为我们不想在真正的渗透测试过程中损害系统的完整性。

所以 backup.sh 的内容应如下图：

![](https://i.imgur.com/nCCrhGX.png)

我们现在将在我们的攻击机器上运行一个监听器来接收传入的连接。

![](https://i.imgur.com/bmOh0CG.png)

Crontab 始终值得检查，因为它有时会导致简单的特权升级向量。以下场景在不具备一定网络安全成熟度级别的公司中并不少见：

1. 因为系统管理员需要定期运行脚本。
2. 所以他们创建了一个定时任务来执行此操作
3. 一段时间后，脚本变得无用，所以他们将脚本删除了。
4. 但他们未清理相关的定时任务

此变更管理问题导致利用定时任务的潜在漏洞。

![](https://i.imgur.com/rPipHqi.png)

上面的示例显示了类似的情况，其中删除了 antivirus.sh 脚本，但定时任务仍然存在。

如果未定义脚本的完整路径（如对 backup.sh 脚本所做的那样），cron 将引用 /etc/crontab 文件中 PATH 变量下列出的路径。在这种情况下，我们应该能够在用户的主文件夹下创建一个名为“antivirus.sh”的脚本，它应该由定时任务运行。

目标系统上的文件应该看起来很熟悉：

![](https://i.imgur.com/tScWLdO.png)

传入的反向 shell 连接具有 root 权限：

![](https://i.imgur.com/WtNhmNr.png)

在奇怪的情况下，您会发现一个现有的脚本或任务附加到定时任务。花时间了解脚本的功能以及如何在上下文中使用任何工具总是值得的。
例如，tar、7z、rsync 等，可以使用它们的通配符功能进行利用。


## PATH 环境变量提权

如果您对位于 PATH 中的某文件夹有写入权限，那么您可能会劫持应用程序来运行脚本。

Linux 中的 PATH 是一个环境变量，它告诉操作系统在哪里搜索可执行文件。对于任何未内置于 shell 中或未使用绝对路径定义的命令，Linux 将首先在 PATH 下定义的文件夹中搜索。 （这里说的 PATH 是环境变量，path 是文件所在的位置）。

通常 PATH 看起来像这样：

![](https://i.imgur.com/ElAmN96.png)

如果我们在命令行中键入 “thm” ，Linux 将在这些位置查找名为 thm 的可执行文件。

下面的场景将使您更好地了解如何利用它来提高我们的特权级别。正如您将看到的，这完全取决于目标系统的现有配置，因此请确保您在尝试之前能够回答以下问题。

1. \$PATH 下有哪些文件夹 
2. 您当前的用户是否对这些文件夹中的任何一个具有写入权限？ 
3. 你能修改\$PATH吗？ 
4. 是否有您可以启动的脚本/应用程序会受此漏洞影响？

出于演示目的，我们将使用以下脚本：

![](https://i.imgur.com/caIhwuq.png)

该脚本尝试启动一个名为“thm”的系统二进制文件，但该示例可以很容易地用任何二进制文件复制。 我们将其编译成可执行文件并设置 SUID 位。

![](https://i.imgur.com/4klEON4.png)

我们的用户现在可以访问设置了 SUID 位的 “path” 脚本。

![](https://i.imgur.com/Rip3CqD.png)

执行后， “path” 将在 PATH 下列出的文件夹中查找名为 “thm” 的可执行文件。 

如果 PATH 下列出了任何可写文件夹，我们可以在该目录下创建一个名为 thm 的二进制文件，并让我们的 “path” 脚本运行它。

由于设置了 SUID 位，此二进制文件将以 root 权限运行。可以使用 “`find / -writable 2>/dev/null`” 命令简单地搜索可写文件夹。可以使用简单的剪切和排序序列清理此命令的输出。

![](https://i.imgur.com/ru1UCaC.png)

一些 CTF 场景可以呈现不同的文件夹，但常规系统会输出如上所示的内容。 将其与 PATH 进行比较将帮助我们找到可以使用的文件夹。

![](https://i.imgur.com/o5jhYHh.png)

另一种方法是下面的命令
`find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u`

我们添加了 “`grep -v proc`” 以消除与运行进程相关的许多结果。 不幸的是，/usr 下的子文件夹不可写 更容易写入的文件夹可能是 /tmp。此时因为 /tmp 不存在于 PATH 中，所以我们需要添加它。正如我们在下面看到的，“`export PATH=/tmp:$PATH`” 命令完成了这个。

![](https://i.imgur.com/FOsmdmD.png)

此时，path 脚本还将在 /tmp 文件夹下查找名为 “thm” 的可执行文件。 通过将 /bin/bash 复制为 /tmp 文件夹下的 “thm” ，创建此命令相当容易。

![](https://i.imgur.com/O6wJuvW.png)

我们已经为我们的 /bin/bash 副本赋予了可执行权限，请注意，此时它将以我们用户的权限运行。在此上下文中使提权成为可能的原因是 path 脚本以 root 权限运行，这样就会查找到 /tmp 目录下的 thm 文件，进而执行 /bin/bash 获得一个 root 的 shell。

![](https://i.imgur.com/Ftwui7V.png)

**回答以下问题** 
1. 您具有写入权限的奇怪文件夹是什么？ 

2. 利用$PATH漏洞读取 flag6.txt 文件内容。 

提示：您可以将可写目录添加到用户的 PATH 并创建一个名为“thm”的文件，“./test”可执行文件将读取该文件。 

3. flag6.txt 文件的内容是什么？


## 0x10 NFS 提权

提权的手段并不局限于内部访问。共享文件夹和远程管理界面（例如 SSH 和 Telnet）也可以帮助您获得目标系统的 root 权限。
某些情况下还需要同时使用这两种载体，例如在目标系统上找到 root 级别的 SSH 私钥并通过 SSH 以 root 权限连接，而不是尝试提升当前用户的权限级别。 

另一个与 CTF 和考试更相关的向量是错误配置的网络 shell 。当存在网络备份系统时，有时可以在渗透测试过程中看到此向量。

NFS（网络文件共享）配置保存在 /etc/exports 文件中。该文件是在 NFS 服务器安装期间创建的，通常可供用户读取。

![](https://i.imgur.com/PfsGpPF.png)

nfs 提权的关键是您在上面看到的 “no_root_squash” 选项。默认情况下，NFS 会将 root 用户更改为 nfsnobody 并禁止任何文件以 root 权限执行。
但是如果可写共享上存在 “no_root_squash” 选项，我们可以创建一个设置了 SUID 位的可执行文件并在目标系统上运行它。 

我们将从枚举攻击机器的可挂载共享开始。

![](https://i.imgur.com/WpY7yfm.png)

![](https://i.imgur.com/z5hAZK1.png)

我们将把其中一个 “no_root_squash” 共享挂载到我们的攻击机器上并开始构建我们的可执行文件

![](https://i.imgur.com/GAgIMQw.png)

-o rw：用可读写模式挂上。

由于我们可以设置 SUID 位，因此将在目标系统上运行 /bin/bash 的简单可执行文件将完成这项工作。

![](https://i.imgur.com/Zb2J7Gn.png)

编译代码后，我们将设置 SUID 位。

![](https://i.imgur.com/o0QK7u2.png)

您将在下面看到这两个文件（nfs.c 和 nfs 存在于目标系统上。我们已经处理了挂载的共享，因此无需传输它们）。

![](https://i.imgur.com/V8Yhpe7.png)

请注意，nfs 可执行文件在目标系统上设置了 SUID 位，并以 root 权限运行。

**回答以下问题：**

您可以在目标系统上识别出多少个可挂载共享？ 提交 有多少股启用了 “no_root_squash” 选项？ 提交 在目标系统上获得 root shell 完全的 flag7.txt 文件的内容是什么？


## 0x11 终章

到目前为止，您已经相当了解 Linux 上的主要提权手段，这个挑战应该相当容易。 您已获得对大型科学设施的 SSH 访问权限。尝试提升您的权限，直到您成为 Root。 我们设计这个房间是为了帮助您构建一套完整的 Linux 权限升级方法，这将在 OSCP 等考试和您的渗透测试活动中非常有用。 不要遗漏任何特权升级向量，提权通常更像是一门艺术而不是一门科学。 您可以通过浏览器访问目标计算机或使用下面的 SSH 凭据。 

- 用户名：leonard 
- 密码：Penny123


### WP链接

https://ilkerburak.medium.com/capstone-challenge-tryhackme-writeup-2a28d560f84b