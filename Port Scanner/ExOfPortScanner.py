import socket
from datetime import datetime
import threading

# Use multithreading to scan ports
# Lock for threading for print statements
print_lock = threading.Lock()

def port_scan(target, port):
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(1)
    try:
        scanner.connect((target, port))
        with print_lock:
            print(f"Port {port} is open")
        scanner.close()
    except (socket.timeout, socket.error):
        with print_lock:
            print(f"Port {port} is closed")
        scanner.close()

def threader():
    while True:
        worker = q.get()
        port_scan(target, worker)
        q.task_done()

def main():
    global target, q
    target = input("IP address or hostname to scan: ")
    start_port = int(input("The start port number: "))
    end_port = int(input("The end port number: "))
    threads = int(input("The number of threads to use: "))
    
    # Resolving the IP address
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid hostname.")
        return
    
    # # Timing the scan
    # start_time = datetime.now()

    # Queue for threading
    from queue import Queue
    q = Queue()
    
    # Starting threads
    for x in range(threads):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    
    # Adding ports to the queue
    for port in range(start_port, end_port + 1):
        q.put(port)
    
    # Waiting for the threads to complete
    q.join()
    
    # # Time taken for the scan
    # end_time = datetime.now()
    # total_time = end_time - start_time
    # print(f"Scan completed in {total_time}")

if __name__ == "__main__":
    main()
