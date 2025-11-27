import socket

def get_banner(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((host, port))

        
        if port in [80, 443]:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner

    except:
        return None
    finally:
        sock.close()
