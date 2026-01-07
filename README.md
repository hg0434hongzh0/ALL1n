# ALL1n-通用POC渗透测试框架
为安全研究人员编写的漏洞本地验证库：一个基于Go语言和Fyne GUI框架开发的通用POC（Proof of Concept）渗透测试工具，支持树形结构管理POC、单点/批量测试、数据持久化等功能。
<img width="1193" height="822" alt="image" src="https://github.com/user-attachments/assets/13a4e72f-a9ea-477a-8742-d9a2d3f1e200" />
漏洞数据本地以data.json存储，可以研究一下直接把nuclei的POC搞过来，调一下格式差异即可，后续开发研究研究。
互相传漏洞直接COPY data.json，fyne图形化难搞的一批，有可能会出现报一个错然后整个窗口被拉得巨长。
后续每个洞加入多次请求功能

现在这个版本我觉得不如Yakit的web fuzzer(悲
