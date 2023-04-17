import dns.resolver
import pandas as pd
import re
import json
import concurrent.futures

pattern = re.compile(r"[^.,\s]*cloudflare[^.,\s]*[.,]?", re.IGNORECASE)
# list of websites
farsiweb1 = pd.read_csv('./chunk0.csv')
websites = [url for url in farsiweb1.loc[:, 'domain']][700: 800]
threads = 10
chunklength = len(websites) // threads
input_urls = [websites[i: i + chunklength] for i in range(0, len(websites), chunklength)]

def scanner(websites):
    # dictionary to store the results
    results = {}
    for website in websites:
        try:
            ips = []
            name_servers = []
            # resolve the A records for the website
            a_records = dns.resolver.resolve(website, 'A')
            for rdata in a_records:
                ips.append(rdata.to_text())
            # resolve the NS records for the website
            ns_records = dns.resolver.resolve(website, 'NS')
            for rdata in ns_records:
                name_servers.append(rdata.to_text().lower())
            # store the results in the dictionary
            results[website] = {'ips': ips, 'ns': name_servers} 
        except Exception as e:
            #print(f"Error resolving {website}: {e}")
            continue
    
    outlist = []
    for url, detail in results.items():
        for ns in detail['ns']:
            if pattern.findall(ns):
                print(f'{url} ====== {detail["ips"]}')
                outlist.append((url, detail["ips"]))
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
i_num = 0
for lists in output:
    for webgroup in lists:
        cf_webaddresses.append(webgroup[0])
        for ips in webgroup[1]:
            ip_list.append(ips)


scanips = {}
scanips["workingIPs"] = []
for ip in ip_list:
    if ip:
        i_num += 1
        scanips["workingIPs"].append({"delay": i_num, "ip": ip})
    else:
        continue
print(f'total ips: {i_num}')
scanips["totalFoundWorkingIPs"] = i_num
scanips["totalFoundWorkingIPsCurrentRange"] = i_num
scanips["startDate"] = "2023-04-04T10:41:35.5737055-07:00"
scanips["endDate"] = "2023-04-04T10:41:35.5737056-07:05"

with open('ips.json', 'w') as f:
    json.dump(scanips, f)

with open("url_cloudflare.txt", "w") as f:
    f.write("\n".join(cf_webaddresses))
