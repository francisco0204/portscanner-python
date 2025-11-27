import socket
import threading

host = "scanme.nmap.org"

def scan_port(port):
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
        print(f"🔥 Puerto {port} abierto")
    except:
        pass
    finally:
        sock.close()

for port in range(1, 1025):
    thread = threading.Thread(target=scan_port, args=(port,))
    thread.start()
