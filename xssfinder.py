import requests
import re
import argparse
import os
import sys
import time

from huepy import *
from core import requester
from core import extractor
from urllib.parse import unquote

start_time = time.time()

def clear():
    if 'linux' in sys.platform:
        os.system('clear')
    elif 'darwin' in sys.platform:
        os.system('clear')
    else:
        os.system('cls')

def banner():
    ban = '''
                ____         __       
 __ __ ___ ___ / _(_)__  ___/ /__ ____
 \ \ /(_-<(_-</ _/ / _ \/ _  / -_) __/
/_\_\/___/___/_//_/_//_/\_,_/\__/_/   
                                      v1.0
                                       '''

    print(cyan(ban))

def main():
    parser = argparse.ArgumentParser(description='xssfinder - a xss scanner tool')
    parser.add_argument('-d', '--domain', help = 'Domain name of the target [ex. example.com]', required=True)
    parser.add_argument('-s', '--subs', help = 'Set false or true [ex: --subs False]', default=False)
    args = parser.parse_args()

    if args.subs == True:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
    else:
        url = f"http://web.archive.org/cdx/search/cdx?url={args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"

    response = requester.connector(url)
    if response == False:
        return
    response = unquote(response)

    exclude = ['woff', 'js', 'ttf', 'otf', 'eot', 'svg', 'png', 'jpg']
    final_uris = extractor.param_extract(response , "high", exclude, "")

    file = open('payloads.txt', 'r')
    payloads = file.read().splitlines()

    for i in final_uris:
        for j in payloads:
            url = final_uris+payloads
        print(url)

if __name__ == "__main__":
    clear()
    banner()
    main()