import requests
import threading

domain="youtube.com"

with open('subdomain.txt') as file:
    subdomains=file.read().splitlines()

discovered_subdomains=[]
lock=threading.Lock()

def check_subdomain(subdomain):

    url=f'http://{subdomain}.{domain}'
    try:
        requests.get(url)
    except requests.ConnectionError as e:
        print(f"[ERROR] {url} - {e}")

    else:
        print("* Discovered subdomains: ",url)
        with lock:
            discovered_subdomains.append(url)
threads=[]
for subdomain in subdomains:
    print("Checking:", subdomain)
    thread=threading.Thread(target=check_subdomain,args=(subdomain,))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()

with open("discovered_subdomains.txt",'w') as f:
    for subdomain in discovered_subdomains:
        print(subdomain,file=f)
        