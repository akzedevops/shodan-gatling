#!/bin/bash

# Function to perform cleanup before starting a new scan
cleanup() {
    rm -f shodan_results.txt   # Remove the previous Shodan results file
    rm -f ip_addresses.txt     # Remove the previous IP addresses file
    rm -f nmap_results.txt     # Remove the previous Nmap scan results
    rm -f vulnerable_hosts.txt # Remove the previous vulnerability results
}

# Function for debugging messages
debug_message() {
    echo "[DEBUG] $1"
}

# Function to display text in red
red_text() {
    echo -e "\e[31m$1\e[0m"
}

# Function to perform Nmap scanning
perform_nmap_scan() {
    local ip="$1"
    local output_file="$2"
    local vuln_file="$3"
    
    debug_message "Scanning $ip for EternalBlue vulnerability on port 445..."
    
    # Run Nmap and append the output to the specified output file
    nmap -p 445 --script smb-vuln-ms17-010 --open -v "$ip" >> "$output_file"
    
    # Check if the Nmap output contains information about the vulnerability
    if grep -q "A critical remote code execution vulnerability exists" "$output_file"; then
        echo "$ip | A critical remote code execution vulnerability exists in Microsoft SMBv1" >> "$vuln_file"
        red_text "Vulnerable Host: $ip"
    fi
}

# Call the cleanup function to ensure a clean start
cleanup

# Prompt the user for the target country
read -p "Enter the target country: " target_country

# Create an output file to save the scan results
output_file="nmap_results.txt"

# Create a vulnerability file to save vulnerable hosts
vulnerable_hosts="vulnerable_hosts.txt"

# Set the maximum number of concurrent scans
max_concurrent_scans=5

# Counter for the number of hosts scanned
host_count=0

# Loop to scan up to 1000 hosts without duplication
while [ "$host_count" -lt 1000 ]; do
    # Perform a Shodan search for IP addresses with port 445 open in the specified country and running Windows 7
    debug_message "Performing Shodan search (batch $((host_count / 1000 + 1)))..."
    shodan search "country:$target_country port:445 os:Windows 7" --limit $((1000 - host_count)) > shodan_results.txt
    
    # Extract the IP addresses from the Shodan results and save them to a temporary file
    debug_message "Extracting IP addresses..."
    awk -F '\t' '{print $1}' shodan_results.txt > ip_addresses_temp.txt
    
    # Deduplicate and append the IP addresses to the main IP addresses file
    sort -u ip_addresses_temp.txt >> ip_addresses.txt
    
    # Remove the temporary file
    rm -f ip_addresses_temp.txt
    
    # Loop through each IP address in this batch and perform Nmap scans
    while IFS= read -r ip; do
        if [ "$host_count" -ge 1000 ]; then
            break  # Limit reached
        fi
        
        # Call the function within a subshell using bash -c
        (perform_nmap_scan "$ip" "$output_file" "$vulnerable_hosts") &
        host_count=$((host_count + 1))
    done < ip_addresses.txt
    
    # Wait for all scans in this batch to complete
    wait
done

# Display the vulnerable results in red
echo "Vulnerable Hosts:"
red_text "$(cat "$vulnerable_hosts")"

echo "Results saved to $vulnerable_hosts"
