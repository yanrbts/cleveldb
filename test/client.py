import socket
import time

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_test_packets():
    messages = [
        "Hello from Python!",
        "io_uring is extremely fast.",
        "Industrial VPN development in progress...",
        "END_TEST"
    ]
    
    for msg in messages:
        print(f"Sending: {msg}")
        sock.sendto(msg.encode(), (SERVER_IP, SERVER_PORT))
        time.sleep(1) # Interval for clarity in console

if __name__ == "__main__":
    try:
        send_test_packets()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()