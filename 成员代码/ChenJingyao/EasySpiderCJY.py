#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 导入必要的库
import requests
from bs4 import BeautifulSoup
import time
import random
from datetime import datetime

# 定义一个爬虫类
class SimpleSpider:
    """
    简单的网页爬虫类
    用于抓取网页的标题和链接
    """
    
    def __init__(self):
        """
        初始化爬虫
        设置请求头和基础参数
        """
        # 设置请求头，模拟浏览器访问
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # 设置超时时间
        self.timeout = 10
        # 设置重试次数
        self.max_retries = 3
        
    def get_page(self, url):
        """
        获取网页内容
        参数：
            url: 要访问的网页地址
        返回：
            网页内容或错误信息
        """
        # 重试机制
        for i in range(self.max_retries):
            try:
                # 发送GET请求
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                # 检查响应状态
                response.raise_for_status()
                # 设置编码
                response.encoding = 'utf-8'
                return response.text
            except Exception as e:
                print(f"第{i+1}次请求失败: {str(e)}")
                if i < self.max_retries - 1:
                    # 随机等待一段时间后重试
                    time.sleep(random.uniform(1, 3))
                else:
                    return None
    
    def parse_page(self, html):
        """
        解析网页内容
        参数：
            html: 网页HTML内容
        返回：
            解析后的数据列表
        """
        if not html:
            return []
            
        # 使用BeautifulSoup解析HTML
        soup = BeautifulSoup(html, 'html.parser')
        results = []
        
        try:
            # 获取页面标题
            title = soup.title.string.strip() if soup.title else "无标题"
            
            # 获取所有链接
            for link in soup.find_all('a'):
                href = link.get('href')
                text = link.get_text().strip()
                
                # 只保存有效的链接
                if href and (href.startswith('http://') or href.startswith('https://')):
                    results.append({
                        'title': text or '无文本',
                        'url': href
                    })
                    
            return results
        except Exception as e:
            print(f"解析页面时出错: {str(e)}")
            return []
    
    def save_results(self, results, filename=None):
        """
        保存结果到文件
        参数：
            results: 要保存的数据
            filename: 文件名（可选）
        """
        if filename is None:
            # 使用当前时间作为默认文件名
            filename = f"spider_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
        try:
            # 打开文件并写入
            f = open(filename, 'w', encoding='utf-8')
            f.write(f"爬取时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n")
            
            # 写入每个结果
            for item in results:
                f.write(f"标题: {item['title']}\n")
                f.write(f"链接: {item['url']}\n")
                f.write("-" * 30 + "\n")
                
            f.close()  # 关闭文件
            print(f"结果已保存到文件: {filename}")
            return True
        except Exception as e:
            print(f"保存结果时出错: {str(e)}")
            return False

def main():
    """
    主函数，程序的入口点
    """
    # 创建爬虫实例
    spider = SimpleSpider()
    
    # 获取用户输入的URL
    print("请输入要爬取的网页地址:")
    url = input().strip()
    
    if not url:
        print("URL不能为空！")
        return
        
    print(f"开始爬取: {url}")
    
    # 获取网页内容
    html = spider.get_page(url)
    if not html:
        print("获取网页内容失败！")
        return
        
    # 解析网页内容
    results = spider.parse_page(html)
    if not results:
        print("未找到任何链接！")
        return
        
    # 显示结果数量
    print(f"共找到 {len(results)} 个链接")
    
    # 保存结果
    spider.save_results(results)

if __name__ == "__main__":
    main()
