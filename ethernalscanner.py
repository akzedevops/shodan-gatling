import os
import subprocess
import shodan

api_key = "YOUR_SHODAN_API_KEY"  # Replace with your Shodan API key
api = shodan.Shodan(api_key)

def cleanup():
    files_to_remove = ["shodan_results.txt", "ip_addresses.txt", "nmap_results.txt", "vulnerable_hosts.txt"]
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)

def debug_message(message):
    print(f"[DEBUG] {message}")

def red_text(text):
    print(f"\033[31m{text}\033[0m")

def perform_nmap_scan(ip, output_file, vuln_file):
    debug_message(f"Scanning {ip} for EternalBlue vulnerability on port 445...")

    nmap_output = subprocess.check_output(["nmap", "-p", "445", "--script", "smb-vuln-ms17-010", "--open", "-v", ip], text=True)

    with open(output_file, "a") as file:
        file.write(nmap_output)

    if "A critical remote code execution vulnerability exists" in nmap_output:
        with open(vuln_file, 'a') as vuln:
            vuln.write(f"{ip} | A critical remote code execution vulnerability exists in Microsoft SMBv1\n")
        red_text(f"Vulnerable Host: {ip}")

cleanup()

target_country = input("Enter the target country: ")

output_file = "nmap_results.txt"

vulnerable_hosts = open("vulnerable_hosts.txt", "a")

max_concurrent_scans = 5

host_count = 0

if not os.path.exists("ip_addresses.txt"):
    open("ip_addresses.txt", "a").close()

while host_count < 1000:
    debug_message(f"Performing Shodan search (batch {host_count // 1000 + 1})...")
    try:
        results = api.search(f'country:{target_country} port:445 os:"Windows 7"', limit=1000 - host_count)
    except shodan.APIError as e:
        print(f"Error: {e}")
        break

    with open("shodan_results.txt", "w") as shodan_results:
        for result in results['matches']:
            shodan_results.write(f"{result['ip_str']}\n")

    debug_message("Extracting IP addresses...")
    with open("shodan_results.txt", "r") as shodan_results:
        ip_addresses_temp = [line.strip() for line in shodan_results]

    with open("ip_addresses.txt", "a") as ip_addresses:
        for ip in ip_addresses_temp:
            if ip not in open("ip_addresses.txt").read():
                ip_addresses.write(f"{ip}\n")

    for ip in ip_addresses_temp:
        if host_count >= 1000:
            break  

        perform_nmap_scan(ip, output_file, vulnerable_hosts)
        host_count += 1

    # Check if there are no more IPs in the ip_addresses.txt file, and if so, break the loop
    with open("ip_addresses.txt", "r") as ip_addresses:
        if not ip_addresses.read():
            break

print("Vulnerable Hosts:")
with open("vulnerable_hosts.txt", "r") as vuln_hosts:
    for line in vuln_hosts:
        red_text(line)

print("Results saved to vulnerable_hosts.txt")
