def main():
    with open("sample.log") as f:
        ip_counts = {}
        for line in f:
            if "Failed login" in line:
                text = line.split("from", 1)
                ip = text[1].strip()
                print(f"Extracted IP: '{ip}'")
                
                if ip in ip_counts:
                    ip_counts[ip] += 1
                else:
                    ip_counts[ip] = 1
                
                print(ip_counts)

main()
