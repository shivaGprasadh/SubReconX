import requests
import socket
import dns.resolver
import csv
import os


# Passive Subdomain Enumeration (crt.sh & AlienVault OTX)
def passive_dns(domain):
    subdomains = {}

    # crt.sh lookup
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomain = entry["name_value"]
                for sub in subdomain.split("\n"):
                    subdomains[sub] = {"method": "Passive"}
    except Exception as e:
        print(f"[!] crt.sh error: {e}")

    # AlienVault OTX lookup
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        response = requests.get(otx_url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            data = response.json()
            for record in data.get("passive_dns", []):
                subdomains[record["hostname"]] = {"method": "Passive"}
    except Exception as e:
        print(f"[!] AlienVault OTX error: {e}")

    return subdomains


# Active DNS Brute-Force (Using a wordlist)
def active_dns(domain, wordlist):
    subdomains = {}

    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(subdomain, "A")
            subdomains[subdomain] = {"method": "Wordlist"}
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer):
            continue
    return subdomains


# Check if a subdomain is active and get its IP address
def check_active(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return "Active", ip
    except socket.gaierror:
        return "Inactive", "N/A"


# Load a wordlist for brute-force
def load_wordlist(filepath):
    if not filepath:
        return None  # Skip brute-force if wordlist is not provided

    try:
        with open(filepath, "r") as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print("[!] Wordlist file not found.")
        return None


# Save results to CSV
def save_to_csv(results, output_path):
    csv_file = os.path.join(output_path, "subdomains_results.csv")
    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Domain", "Status", "IP Address", "Method"])
        for domain, info in results.items():
            writer.writerow([domain, info["status"], info["ip"], info["method"]])

    print(f"\n[✔] Results saved to: {csv_file}")


# Main function
def main():
    domain = input("Enter the target domain: ").strip()
    wordlist_path = input("Enter wordlist path (press Enter to skip): ").strip()

    print("\n[*] Performing Passive DNS Enumeration...")
    passive_results = passive_dns(domain)

    if wordlist_path:
        print("\n[*] Performing Active DNS Brute-Force Enumeration...")
        wordlist = load_wordlist(wordlist_path)
        if wordlist:
            active_results = active_dns(domain, wordlist)
        else:
            active_results = {}
    else:
        active_results = {}

    # Combine results
    all_subdomains = {**passive_results, **active_results}

    print("\n[*] Checking Active Subdomains...\n")
    for subdomain in all_subdomains.keys():
        status, ip = check_active(subdomain)
        all_subdomains[subdomain]["status"] = status
        all_subdomains[subdomain]["ip"] = ip
        print(f"[{status} ✅] {subdomain} (IP: {ip}) [Method: {all_subdomains[subdomain]['method']}]")

    # Save results to CSV
    save_to_csv(all_subdomains, "/path/to/save")


if __name__ == "__main__":
    main()
