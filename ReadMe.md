# 信息安全管理系统课程开源社区建设

## 项目概述
本项目是信息安全管理课程的开源社区建设作业，旨在通过实践来学习和应用信息安全管理的相关知识。项目采用开源协作的方式，由本课程小组成员共同维护和开发。
(Open source community construction of information security management course)

## 项目结构
```
.
├── 漏洞靶场/          # 存放选定的漏洞靶场代码
└── 成员代码/          # 存放各成员开发的代码
    └── ChenJingyao/   # 成员陈璟耀个人代码目录
        └── EasySpiderCJY.py  # 网页爬虫工具
```

## 功能说明

### 成员代码/ChenJingyao/EasySpiderCJY.py
这是一个简单但功能完整的网页爬虫工具，主要功能包括：

- 网页内容抓取：支持通过URL获取网页内容
- 智能解析：使用BeautifulSoup解析HTML，提取标题和链接
- 错误处理：包含重试机制和异常处理
- 结果保存：支持将爬取结果保存到本地文件
