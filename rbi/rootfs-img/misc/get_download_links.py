#coding=utf-8
from bs4 import BeautifulSoup
import requests
PREFIX = "https://rpmfind.net"

packages = [['xfsprogs','5.10.0-2.fc34'],['inih','49-3.fc34'],['libedit','3.1-37.20210522cvs.fc34']]

for p in packages:
    software = p[0]
    version = p[1]
    html = requests.get('https://rpmfind.net/linux/rpm2html/search.php?query=' + software + '&submit=Search+...&system=Fedora+34&arch=x86_64')
    soup = BeautifulSoup(html.content,'lxml')
 
    links = soup.find_all('td')
    for link in links:
        if link.a:
            if link.a['href']:
                lk = link.a['href']
                if version in lk and not ("html" in lk) and not ('test' in lk) and not ('rawhide' in lk):
                    print(software + " " + PREFIX + lk)

