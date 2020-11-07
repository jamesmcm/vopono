# Parser for https://www.ivpn.net/clientarea/vpn/273887/wireguard/servers
# As it is behind captcha login

import bs4
import csv
from typing import List, Dict

with open("ivpn_wg.html", "r") as file:
    html = file.read()
    soup = bs4.BeautifulSoup(html, "html.parser")

    hosts: List[Dict[str, str]] = []
    b = soup.find("div", {"class": "row"})
    while True:
        b = b.find_next("div", {"class": "col-xs-12 col-md-3"})
        if b:
            country = b.contents[4].strip()
            country = country.replace(",", "-").replace(" ", "")
            country = country.lower()
            # Fix GB -> UK country code
            country = country.replace("gb-", "uk-")
            b = b.find_next("div", {"class": "col-xs-6 col-md-3"})
            hostname = b.contents[2].strip()
            b = b.find_next("div", {"class": "col-xs-6 col-md-2"})
            ip = b.contents[2].strip()
            b = b.find_next("div", {"class": "col-xs-12 col-md-4"})
            b = b.find_next("span")
            key = b.text.strip()
            print(f"{country}|{hostname}|{ip}|{key}")
            hosts.append(
                {"country": country, "hostname": hostname, "ip": ip, "pubkey": key}
            )
        else:
            break

    with open("ivpn_wg_hosts.csv", "w") as csvfile:
        fieldnames = ["country", "hostname", "ip", "pubkey"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for host in hosts:
            writer.writerow(host)
