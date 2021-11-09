print('1 - DNS Lookup - URL')
print('2 - Reverse DNS Lookup - IP Address')
print('3 - GeoIP Lookup API - IP Address')
print('4 - Reverse IP Lookup - IP Address')
print('5 - HTTP Headers - URL')
print('6 - Page Links - URL')
print('7 - AS Lookup - IP Address')

import requests

def main():

		request = requests.get(url)
		response = request.text
		print(response)

tool = int(input('pick your tool: '))
target = input('enter url/IP: ')

if tool == 1:
    url = "https://api.hackertarget.com/dnslookup/?q=" + target
elif tool == 2:
    url = "https://api.hackertarget.com/reversedns/?q=" + target
elif tool == 3:
    url = "https://api.hackertarget.com/geoip/?q=" + target
elif tool == 4:
    url = "https://api.hackertarget.com/reverseiplookup/?q=" + target
elif tool == 5:
    url = "https://api.hackertarget.com/httpheaders/?q=" + target
elif tool == 6:
    url = "https://api.hackertarget.com/pagelinks/?q=" + target
elif tool == 7:
    url = "https://api.hackertarget.com/aslookup/?q=" + target

main()
