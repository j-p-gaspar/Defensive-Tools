import re

def extract_unique_ips(text):
    # Regex pattern to match IPv4 addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    # Find all IPs in the text
    found_ips = re.findall(ip_pattern, text)
    
    # Remove duplicates using a set
    unique_ips = list(set(found_ips))
    
    return unique_ips, len(unique_ips)

if __name__ == "__main__":
    try:
        while True:
            # Prompt user for input text
            user_input = input("Enter text containing IP addresses:\n")
        
            # Process the input
            ips, total = extract_unique_ips(user_input)
        
            # Display results
            print("\nUnique IPs found:")
            for ip in ips:
                print(f"- {ip}")
            
            print(f"\nTotal unique IPs: {total}\n")
    except KeyboardInterrupt:
        print("\n\nExiting... Goodbye! 👋")
