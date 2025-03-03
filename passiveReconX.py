import requests
import csv
import time


# Retry logic for stable requests
def retry_request(url, retries=3, timeout=30):
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                return response
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
        time.sleep(2)
    return None


# Passive enumeration
def passive_dns(domain):
    subdomains = set()
    print("[*] Gathering subdomains from passive sources...")

    # crt.sh
    crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = retry_request(crt_url)
    if response:
        try:
            data = response.json()
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                subdomains.update(names)
        except Exception as e:
            print(f"[!] Error parsing crt.sh response: {e}")

    # AlienVault OTX
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    response = retry_request(otx_url, timeout=10)
    if response:
        try:
            data = response.json()
            for record in data.get("passive_dns", []):
                subdomains.add(record["hostname"])
        except Exception as e:
            print(f"[!] Error parsing AlienVault OTX response: {e}")

    # RapidDNS
    rapid_url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    response = retry_request(rapid_url)
    if response:
        try:
            text = response.text
            for line in text.splitlines():
                if domain in line:
                    subdomains.add(line.strip())
        except Exception as e:
            print(f"[!] Error parsing RapidDNS response: {e}")

    print(f"[*] Passive sources found: {len(subdomains)} unique subdomains.")
    return subdomains


# Save subdomains to CSV
def save_to_csv(subdomains, output_path):
    try:
        with open(output_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Subdomain"])
            for subdomain in sorted(subdomains):
                writer.writerow([subdomain])
        print(f"[+] Subdomains saved to {output_path}")
    except Exception as e:
        print(f"[!] Error writing CSV: {e}")


# Main
def main():
    domain = input("Enter the target domain: ").strip()
    output_path = "/Users/sivaprasath/Downloads/subdomains.csv"

    subdomains = passive_dns(domain)
    save_to_csv(subdomains, output_path)


if __name__ == "__main__":
    main()
