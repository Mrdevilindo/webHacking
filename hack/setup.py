#!/usr/bin/env python
# coding: utf-8

import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter

# external modules
from subbrute import subbrute
import dns.resolver
import requests

# Python 2.x and 3.x compatibility
if sys.version > '3':
    import urllib.parse as urlparse
    import urllib.parse as urllib
else:
    import urlparse
    import urllib

# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Check if we are running this on the Windows platform
is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    # Windows deserves coloring too :D
    G = ''  # green
    Y = ''  # yellow
    B = ''  # blue
    R = ''  # red
    W = ''  # white
    try:
        import win_unicode_console
        import colorama
        win_unicode_console.enable()
        colorama.init()
        # Now the unicode will work ^_^
    except:
        pass
else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white


def banner():
    print(G + """
          $$\      $$\                 $$\                    $$\ $$\ $$\                 $$\           
$$$\    $$$ |                $$ |                   \__|$$ |\__|                $$ |          
$$$$\  $$$$ | $$$$$$\   $$$$$$$ | $$$$$$\$$\    $$\ $$\ $$ |$$\ $$$$$$$\   $$$$$$$ | $$$$$$\  
$$\$$\$$ $$ |$$  __$$\ $$  __$$ |$$  __$$\$$\  $$  |$$ |$$ |$$ |$$  __$$\ $$  __$$ |$$  __$$\ 
$$ \$$$  $$ |$$ |  \__|$$ /  $$ |$$$$$$$$ \$$\$$  / $$ |$$ |$$ |$$ |  $$ |$$ /  $$ |$$ /  $$ |
$$ |\$  /$$ |$$ |      $$ |  $$ |$$   ____|\$$$  /  $$ |$$ |$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
$$ | \_/ $$ |$$ |      \$$$$$$$ |\$$$$$$$\  \$  /   $$ |$$ |$$ |$$ |  $$ |\$$$$$$$ |\$$$$$$  |
\__|     \__|\__|       \_______| \_______|  \_/    \__|\__|\__|\__|  \__| \_______| \______/ 
                                                                                              
                                by Mr.Indo                                
                        https://github.com/Mrdevilindo 
                          ~~~~DO NOT ERROR SYSTEM~~~~                                                           

""" + W)


# Example usage
banner()


def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(
        epilog='\tExample: \r\npython ' + sys.argv[0] + " -u google.com -l anga13 -w ")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument(
        '-u', '--url', help="Domain name to enumerate its subdomains", required=True)
    parser.add_argument(
        '-l', '--file', help='Enable the username or wordlist username', nargs='?', default=False)
    parser.add_argument(
        '-w', '--word', help='Enable the password or wordlist password', nargs='?', default=False)
    parser.add_argument(
        '-b', '--bruteforce', help='Enable the bruteforce file module', nargs='?', default=False)
    parser.add_argument(
        '-d', '--dirb', help='Enable the dirb module', nargs='?', default=False)
    parser.add_argument(
        '-p', '--ports', help='Scan the found subdomains against specified TCP ports')
    parser.add_argument(
        '-v', '--verbose', help='Enable verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument(
        '-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument(
        '-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument(
        '-o', '--output', help='Save the results to a text file')
    parser.add_argument('-n', '--no-color', help='Output without color',
                        default=False, action='store_true')
    return parser.parse_args()


class EnumratorBase(object):
    MAX_DOMAINS = 1
    MAX_PAGES = 1

    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.print_banner()

    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def print_banner(self):
        """ subclass can override this if they want a fancy banner :)"""
        self.print_(G + "[-] Searching now in %s.." % (self.engine_name) + W)
        return

    def send_req(self, query, page_no=1):
        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(
                url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    # override
    def extract_domains(self, resp):
        """ child class should override this function """
        return []

    # override
    def check_response_errors(self, resp):
        """ child class should override this function
        The function should return True if there are no errors and False otherwise
        """
        return True

    def should_sleep(self):
        """Some enumerators require sleeping to avoid bot detections like Google enumerator"""
        return

    def generate_query(self):
        """ child class should override this function """
        return ""

    def get_page(self, num):
        """ child class that uses different pagination counter should override this function """
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            # finding the number of subdomains found so far
            count = query.count(self.domain)

            # if we reached the maximum number of subdomains in search query
            # then we should go over the pages
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            # maximum pages to avoid getting blocked
            if self.check_max_pages(page_no):
                return self.subdomains
            resp = self.send_req(query, page_no)

            # check if there is any error occurred
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)

            # if the previous page hyperlinks were similar to the current one, then maybe we have reached the last page
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)

                # make another retry maybe it isn't the last page
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains


class MyEnumerator(EnumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        super(MyEnumerator, self).__init__(
            base_url, engine_name, domain, subdomains, silent, verbose)

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" %
                                    (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if (type(resp) is str or type(resp) is unicode) and 'Our systems have detected unusual traffic' in resp:
            self.print_(
                R + "[!] Error: Google probably now is blocking our requests" + W)
            self.print_(R + "[~] Finished now the Google Enumeration ..." + W)
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query


class GoogleEnum(MyEnumerator):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name,
                                         domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" %
                                    (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if (type(resp) is str or type(resp) is unicode) and 'Our systems have detected unusual traffic' in resp:
            self.print_(
                R + "[!] Error: Google probably now is blocking our requests" + W)
            self.print_(R + "[~] Finished now the Google Enumeration ..." + W)
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query


class UserEnumerator(EnumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, usernames=None, silent=False, verbose=True):
        super(UserEnumerator, self).__init__(
            base_url, engine_name, domain, subdomains, silent, verbose)
        self.usernames = usernames

    def extract_domains(self, resp):
        # Implementasikan metode ini sesuai dengan ekstraksi domain dari respons
        return []

    def check_response_errors(self, resp):
        # Implementasikan metode ini sesuai dengan pengecekan error respons
        return True

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

    def enumerate(self):
        # Lakukan pemrosesan enumerasi user sesuai kebutuhan Anda
        if self.usernames:
            for username in self.usernames:
                print("Enumerating user:", username)
                # Lakukan logika enumerasi user
                # ...


class BruteforceEnumerator(EnumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, passwords=None, silent=False, verbose=True):
        super(BruteforceEnumerator, self).__init__(
            base_url, engine_name, domain, subdomains, silent, verbose)
        self.passwords = passwords

    def extract_domains(self, resp):
        # Implementasikan metode ini sesuai dengan ekstraksi domain dari respons
        return []

    def check_response_errors(self, resp):
        # Implementasikan metode ini sesuai dengan pengecekan error respons
        return True

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

    def enumerate(self):
        # Lakukan pemrosesan enumerasi bruteforce sesuai kebutuhan Anda
        if self.passwords:
            for password in self.passwords:
                print("Enumerating password:", password)
                # Lakukan logika enumerasi bruteforce
                # ...


def main():
    args = parse_args()

    # Cek argumen dan panggil objek EnumratorBase atau GoogleEnum sesuai kebutuhan
    if args.url:
        domain = args.url
        enumerator = EnumratorBase(
            "https://example.com", "Example", domain, silent=True, verbose=False)
        subdomains = enumerator.enumerate()

        # Lakukan pemrosesan subdomains sesuai kebutuhan Anda
        for subdomain in subdomains:
            print(subdomain)

    if args.file:
        # Lakukan pemrosesan username sesuai kebutuhan Anda
        if os.path.isfile(args.file):
            with open(args.file, 'r') as f:
                usernames = f.read().splitlines()
            user_enumerator = UserEnumerator(
                "https://example.com", "Example", domain, subdomains, usernames, silent=True, verbose=False)
            user_enumerator.enumerate()

    if args.word:
        # Lakukan pemrosesan password sesuai kebutuhan Anda
        if os.path.isfile(args.word):
            with open(args.word, 'r') as f:
                passwords = f.read().splitlines()
            bruteforce_enumerator = BruteforceEnumerator(
                "https://example.com", "Example", domain, subdomains, passwords, silent=True, verbose=False)
            bruteforce_enumerator.enumerate()


if __name__ == '__main__':
    main()
