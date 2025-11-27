import socket

host = "scanme.nmap.org"

for port in range(1, 1025):
    sock = socket.socket()
    sock.settimeout(0.5)

    try:
        sock.connect((host, port))
        print(f"🔥 Puerto {port} abierto")
    except:
        pass

    sock.close()
