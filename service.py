def identify_service(port, banner):
    if banner:
        banner = banner.lower()

        if "ssh" in banner:
            return "SSH"
        if "http" in banner:
            return "HTTP"
        if "apache" in banner:
            return "Apache Web Server"
        if "nginx" in banner:
            return "Nginx Web Server"
        if "ftp" in banner:
            return "FTP"

    # fallback
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "Remote Desktop",
    }

    return common_ports.get(port, "Unknown")

def extract_software_info(banner):
    if not banner:
        return None, None

    banner = banner.lower()

    # Detectar OpenSSH
    if "openssh" in banner or "ssh-" in banner:
        return "openssh", "openssh"

    # Detectar Apache
    if "apache" in banner:
        return "apache", "http_server"

    # Detectar Nginx
    if "nginx" in banner:
        return "nginx", "nginx"

    return None, None


