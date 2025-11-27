import socket

def scan_port(host, port, timeout=0.5):
    sock = socket.socket()
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        return True
    except:
        return False
    finally:
        sock.close()
