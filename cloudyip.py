import dns.resolver
import re
import json
import concurrent.futures
import csv

pattern = re.compile(r"[^.,\s]*cloudflare[^.,\s]*[.,]?", re.IGNORECASE)

websites = [] # list of websites
with open('./chunk0.csv', 'r') as chunk0:
    csv_reader = csv.reader(chunk0)
    for row in csv_reader:
        websites.append(row[0])
# set max limit search
try:
    how_many = int(input(f'\nHow many url do you want to check?[1-{len(websites)}]:'))
except:
    how_many = len(websites)

if how_many > len(websites):
    how_many = len(websites)
if how_many < 1:
    how_many = 1
# set threads
threads = 10 if how_many >= 10 else 1
input_urls = []
for i in range(0, how_many, threads):
    if (i + threads) < how_many:
        input_urls.append(websites[i: i + threads])
    else:
        input_urls.append(websites[i: how_many])
def scanner(websites):
    # dictionary to save result
    results = {}
    for website in websites:
        try:
            ips = []
            name_servers = []
            ipv6 = []
            # resolve the A records for the website
            a_records = dns.resolver.resolve(website, 'A')
            for rdata in a_records:
                ips.append(rdata.to_text())
            # resolve the AAAA records for the website
            aaaa_records = dns.resolver.resolve(website, 'AAAA')
            for rdata in aaaa_records:
                ipv6.append(rdata.to_text())
            # resolve the NS records for the website
            ns_records = dns.resolver.resolve(website, 'NS')
            for rdata in ns_records:
                name_servers.append(rdata.to_text().lower())
            # store the results in the dictionary
            results[website] = {'ips': ips,'ipv6': ipv6, 'ns': name_servers} 
        except Exception as e:
            #print(f"Error resolving {website}: {e}")
            continue
    
    outlist = []
    for url, detail in results.items():
        for ns in detail['ns']:
            if pattern.findall(ns):
                print(f'\n{url}\n-------------\n{detail["ips"]}\n{detail["ipv6"]}\n-------------')
                outlist.append((url, detail["ips"], detail["ipv6"]))
                break
    return outlist

output = []
with concurrent.futures.ThreadPoolExecutor() as executer:
    tasks = [executer.submit(scanner, url) for url in input_urls]
    for task in concurrent.futures.as_completed(tasks):
        result = task.result()
        output.append(result)

cf_webaddresses = []
ip_list = []
ipv6_list = []
ipv6_num = 0
for lists in output:
    for webgroup in lists:
        cf_webaddresses.append(webgroup[0])
        for ips in webgroup[1]:
            ip_list.append(ips)
        for ipv6s in webgroup[2]:
            ipv6_list.append(ipv6s)
            ipv6_num += 1


scanips = {}
scanips["workingIPs"] = []
ipv4_num = 0
for ip in ip_list:
    if ip:
        ipv4_num += 1
        scanips["workingIPs"].append({"delay": ipv4_num, "ip": ip})
    else:
        continue

print(f'total ipv4: {ipv4_num}')
print(f'total ipv6: {ipv6_num}')
scanips["totalFoundWorkingIPs"] = ipv4_num
scanips["totalFoundWorkingIPsCurrentRange"] = ipv4_num
scanips["startDate"] = "2023-04-04T10:41:35.5737055-07:00"
scanips["endDate"] = "2023-04-04T10:41:35.5737056-07:05"

with open('ip4scan.json', 'w') as f:
    json.dump(scanips, f)

with open('ipv6.txt', 'w') as f:
    f.write("\n".join(ipv6_list))

with open("url_cloudflare.txt", "w") as f:
    f.write("\n".join(cf_webaddresses))