#!/usr/bin/python
#coding:utf-8
#Author:LinAn@123
#目标tcp端口开放扫描及应用端口banner识别

import xlwt
import nmap
import sys
import requests
import re
import threading
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
R=threading.Lock()
book = xlwt.Workbook() #创建Excel


nm = nmap.PortScanner(nmap_search_path=('nmap', r"E:\nmap-7.92\nmap.exe"))

header = {
        'method':'get',
        'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36 Edg/97.0.1072.62'
    }
def nmap_A_scan(host,result):
    if result['status']['state'] == 'up':
        #print (result)
        try:
            for port in result['tcp']:
                if port != 9100:
                    url_http = ('http://' + str(host) + ':' + str(port) + '/')
                    url_https = ('https://' + str(host) + ':' + str(port) + '/')
                    R.acquire()
                    get_html(host,port,url_http)
                    get_html(host, port, url_https)
                    R.release()
        except KeyError as e:
            pass


def get_html(host,port,url):
    try:
        r = requests.get(url, headers=header, timeout=2, verify=False)
        r.encoding = r.apparent_encoding
        if r.status_code == 200:
            loca = re.findall('location.href = \'(.*?)\'', r.text)
            redi = re.findall('document.location="(.*?)"', r.text)
            open = re.findall('window.open\("(.*?)", "_top"\);', r.text)
            if loca:
                url_loca = (url + loca[0])
                get_html_title(host,port,url_loca)
            # print(r.text)
            elif redi:
                url_redi = (url + redi[0])
                get_html_title(host,port,url_redi)

            elif open:
                url_open = (url + open[0])
                get_html_title(host,port,url_open)

            else:
                get_html_title_flag(host,port,url,r.text)
    except requests.exceptions.RequestException as e:
        pass

def get_html_title(host,port,url):
    #跳转url
    # print (url)
    r = requests.get(url, headers=header, timeout=2, verify=False)
    r.encoding = r.apparent_encoding
    if r.status_code == 200:
        get_html_title_flag(host,port,url,r.text)


def get_html_title_flag(host,port,url,text):
    #获取标题
    title = 'not title'
    flag = (url + ' ' + title)
    title = re.findall('<title\s\S*?>\s*?(\S*?)\s*?</title>', text)
    if len(title):
        for i in title:
            if i:
                flag = (url + ' ' + i)
                # print(flag)
    else:
        title = re.findall('<title>(.*?)</title>', text)
        if len(title):
            for i in title:
                if i:
                    flag = (url + ' ' + i)
                    title = i
                    # print(flag)
    print (flag)
    go_to_ex(host,port,url,title)

def go_to_ex(host,port,url,title):
    msg = []
    msg.append(host)
    msg.append(port)
    msg.append(url)
    msg.append(title)
    data.append(msg)
    # print (data)

if __name__ == '__main__':

    # print ('ip地址格式有 192.168.0.1(单个ip)  192.168.0.0/24(单个网段)    192.168.0.1-100(指定区间) ')
    # rw = input('请输入ip地址:')
    rw = '0.0.0.0'
    # nm = nmap.PortScanner()
    # 配置nmap扫描参数
    scan_raw_result = nm.scan(hosts=rw, arguments='-PS -PU -PP -T2 -sS -n')
    # 分析扫描结果
    #print (scan_raw_result)
    #print('-------------')
    #print('-------------')
    data = []
    t10 = []
    for host, result in scan_raw_result['scan'].items():
        #print ('host:' + str(host) + 'result' +str(result))
        t1 = Thread(target=nmap_A_scan(host=host,result=result), args=( host))
        t10.append(t1)
        t1.start()
        t1.join()

    #print('-------------')
    #print('-------------')

    # print ('data:--------------------' + str(data) )
    sheet = book.add_sheet('sheet1')  # 创建sheet页
    title = ['ip地址', '端口号', 'url地址', '标题信息']  # 把表头名称放入list里面
    # 循环把表头写入
    row = 0
    for t in title:
        sheet.write(0, row, t)
        row += 1

    row = 1  # 从表格的第二行开始写入数据
    # 一行一行的写，一行对应的所有列
    for i in range(len(data)):  # 控制行
        alis = data[i]
        for one in range(len(alis)):  # 控制每一列
            sheet.write((i+1), one, alis[one])  # rou代表列，col代表行，one写入值

    book.save('00.xls')

