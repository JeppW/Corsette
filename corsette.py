#!/usr/bin/python

import sys
import requests
from tld import get_tld

target = sys.argv[-1]
agent = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0"
confirm_printed = 0

def strrev(s):
    return s[::-1]

def attempt(ori):
    try:
        return requests.get(target,headers={'Origin': ori,'User-Agent': agent, 'Referer': target, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3','Accept-Encoding': 'none','Accept-Language': 'en-US,en;q=0.8'}, allow_redirects=True)
	print(ori)
    except:
        print("[!] Error occurred... is the target up?\n")
	sys.exit(1)

try:
    o = get_tld(target, as_object=True)
except:
    print("USAGE: python corsette.py <url>")
    sys.exit()
if o.subdomain == "":
	origin = "https://" + o.fld
else:
	origin = "https://" + o.subdomain + "." + o.fld

techniques = [
    ["Origin reflected", "https://notarealdomain.racing"],
    ["Prefix match", origin + ".hacker.com"],
    ["Null origin trusted", "null"],
    ["Unescaped dot bypass", "https://" + o.subdomain + "a" + o.fld],
    ["Suffix match", "https://hacker" + o.fld],
    ["Suffix match (with subdomain)", "https://" + o.subdomain + ".hacker" + o.fld],
    ["TLD change", strrev(strrev(origin)[strrev(origin).index("."):]) + "racing"],

    ["S3 Buckets allowed", "https://evilbucket.s3.amazonaws.com"],
    ["Repl.it pages allowed", "https://constantinbornscript--five-nine.repl.co"],
    ["Github pages allowed", "https://anyname.github.com"],
    ["JSFiddle pages allowed", "https://jsfiddle.net"],
    ["CodePen.io pages allowed", "https://codepen.io"],

    ["Regex escape (Chrome/Firefox)", origin + "_hacker.com"],
    ["Regex escape (Safari)", origin + "`hacker.com"],
    ["Regex escape (Any browser)", strrev(strrev(origin)[strrev(origin).index(strrev(get_tld(origin))):]) + "-hacker.com"],
    ["Regex escape (Safari)", strrev(strrev(origin)[strrev(origin).index(strrev(get_tld(origin))):]) + "=hacker.com"],
]

print("[i] Starting CORS vulnerability scanning on host " + target + "...\n")

for i in techniques:
    res = attempt(i[1])
    if "Access-Control-Allow-Origin" in res.headers and "Access-Control-Allow-Credentials" in res.headers:
	if not confirm_printed:
		print("[i] Site supports CORS and Allow-Credentials\n")
		confirm_printed = 1
	if i[1] == res.headers["Access-Control-Allow-Origin"] and "true" == res.headers["Access-Control-Allow-Credentials"]:
            print("\n[*] Successful exploitation technique discovered:\nTechnique: " + i[0] + "\nOrigin: " + i[1] + "\n")
            sys.exit()
        else:
            print("Attempted origin: " + i[1] + " " * (50 - len(i[1])) + "Allowed origin: " + res.headers["access-control-allow-origin"])
            continue

print("\n[!] No successful techniques were discovered.\n")

