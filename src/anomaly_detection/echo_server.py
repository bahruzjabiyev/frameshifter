import socket
import threading
import re
import sys
import time

class Listener():
    def __init__(self):
        self.request_list = []
        self.batch_num = 0
        self.lock = threading.Lock()

    def handle_connection(self, conn):
        data = b''
        conn_status = b'NO_INFO'
        start_time = None
        duration = b''
        try:
            conn.settimeout(8)
            while True:
                try:
                    conn_data = conn.recv(2048)
                    if not conn_data:
                        end_time = time.time() # get the time when FIN is received
                        if start_time:
                            duration = "{}".format(end_time - start_time).encode()
                            conn_status = duration + b'_FIN_RECEIVED'
                        else:
                            conn_status = b'DIRECT_FIN_RECEIVED'
                        break
                    else:
                        if data == b'': # get the time when data first received
                            start_time = time.time()
                        data += conn_data
                except socket.timeout:
                    conn_status = b'RECV_TIMEOUT'
                    break

            data = conn_status + b';' + data 
            with self.lock:
                if len(self.request_list) == 1000:
                    with open("/logs/requests{}.out".format(self.batch_num), 'w') as outfile:
                        outfile.write("\n".join(self.request_list))
                        outfile.write("\n")

                    self.request_list.clear()
                    self.batch_num = self.batch_num + 1
                else:
                    self.request_list.append("{}".format(data))

            conn.close()
    
        except Exception as exception:
            print("exception {} when received {}.".format(exception, data), file=sys.stderr)

    def _listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 8080))
        s.listen()
        while True:
            try:
                conn, addr = s.accept()
                thread = threading.Thread(target=self.handle_connection, args=(conn,))
                thread.start()
            except Exception as exception:
                print("exception {} when addr is {}.".format(exception, addr), file=sys.stderr)

        s.close()

_listener = Listener()
_listener._listen()
