from sys import argv
import socket
import ssl
import scapy.supersocket as supersocket
#import http2 as h2
import scapy.contrib.http2 as h2
import scapy.config
import scapy.packet as packet
from helper_functions import _print_exception
from base64 import b64encode

class H2Client:

	def __init__(self, verbose=False):
		self.verbose = verbose

	def send(self, dn, port, host_header, seed=0, frames=None):
		try:
			self.seed = seed
			self.target_addr = dn + ":" + str(port)
			self.host_header = host_header
			self.tls_setup_exchange(dn, port)
			self.initial_h2_exchange()
			return self.send_sequence(frames)
		except ConnectionRefusedError:
			print("connection refused at {}:{}.".format(dn, port))
	
	def tls_setup_exchange(self, dn, port, use_insecure_ciphers = False):
		addr_info = socket.getaddrinfo(dn, port, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
		s = socket.socket(addr_info[0][0], addr_info[0][1], addr_info[0][2])
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		if hasattr(socket, 'SO_REUSEPORT'):
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

		ip_and_port = addr_info[0][4]

		ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		ssl_ctx.check_hostname = False
		ssl_ctx.verify_mode = ssl.CERT_NONE

		if use_insecure_ciphers:
			ciphers = ['AES256-GCM-SHA384', 'AES128-GCM-SHA256', 'AES256-SHA256', 'AES128-SHA256', 'CAMELLIA128-SHA256']
		else:
			ciphers = ['ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA384', 'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-CAMELLIA256-SHA384', 'ECDHE-RSA-CAMELLIA256-SHA384', 'ECDHE-ECDSA-CAMELLIA128-SHA256', 'ECDHE-RSA-CAMELLIA128-SHA256', 'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-SHA256', 'DHE-RSA-AES128-SHA256', 'AES256-GCM-SHA384', 'AES128-GCM-SHA256', 'AES256-SHA256', 'AES128-SHA256', 'CAMELLIA128-SHA256']
		ssl_ctx.set_ciphers(':'.join(ciphers))
		ssl_ctx.set_alpn_protocols(['h2'])  # h2 is a RFC7540-hardcoded value

		ssl_sock = ssl_ctx.wrap_socket(s, server_hostname=dn)
		ssl_sock.connect(ip_and_port)
		assert('h2' == ssl_sock.selected_alpn_protocol())
		scapy.config.conf.debug_dissector = True
		ssl_stream_sock = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)
		self.sock = ssl_stream_sock

	def initial_h2_exchange(self):
		# SENDING MAGIC
		magic = packet.Raw(h2.H2_CLIENT_CONNECTION_PREFACE)
		if self.verbose:
			print("-"*32+"SENDING"+"-"*32)
			magic.show()
		self.sock.send(magic)

		# RECEIVING
		srv_set = self.sock.recv()
		if self.verbose:
			print("-"*32+"RECEIVING"+"-"*32)
			srv_set.show()
		srv_max_frm_sz = 1<<14
		srv_hdr_tbl_sz = 4096
		srv_max_hdr_tbl_sz = 0
		srv_global_window = 1<<14
		for setting in srv_set.payload.settings:
			if setting.id == h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE:
				srv_hdr_tbl_sz = setting.value
			elif setting.id == h2.H2Setting.SETTINGS_MAX_HEADER_LIST_SIZE:
				srv_max_hdr_lst_sz = setting.value
			elif setting.id == h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE:
				srv_global_window = setting.value
		
		srv_max_hdr_lst_sz = 1<<10

		own_set = h2.H2Frame()/h2.H2SettingsFrame()
		max_frm_sz = (1 << 24) - 1
		max_hdr_tbl_sz = (1 << 16) - 1
		win_sz = (1 << 31) - 1
		own_set.settings = [
			h2.H2Setting(id = h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
			h2.H2Setting(id = h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
			h2.H2Setting(id = h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
			h2.H2Setting(id = h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
		]

		winupdate = h2.H2Frame(b'\x00\x00\x04\x08\x00\x00\x00\x00\x00\x3f\xff\x00\x01')
		set_ack = h2.H2Frame(flags={'A'})/h2.H2SettingsFrame()

		h2seq = h2.H2Seq()
		h2seq.frames = [
			own_set,
		]
		for frame in h2seq.frames:
			if self.verbose:
				print("-"*32 + "SENDING" + "-"*32)
				frame.show()
			self.sock.send(frame)

		# while loop for waiting until ack is received for client's settings
		new_frame = None
		while isinstance(new_frame, type(None)) or not (
				new_frame.type == h2.H2SettingsFrame.type_id 
				and 'A' in new_frame.flags
			):
			try:
				new_frame = self.sock.recv()
				if self.verbose:
					print("-"*32 + "RECEIVING" + "-"*32)
					new_frame.show()
			except:
				import time
				time.sleep(1)
				new_frame = None


	def send_sequence(self, frames=None):
		if not frames:
			return b'no frame to send.'
		else:
			sequence = h2.H2Seq()
			sequence.frames = frames
			for frame in sequence.frames:
				if self.verbose:
					print("-"*32 + "SENDING" + "-"*32)
					frame.show()
			self.sock.send(sequence)
			
		new_frame = None		
		response_data = b''
		status_codes = []
		error_codes = []
		while True:
			try:
				new_frame = self.sock.recv()
				if self.verbose:
					print("-"*32 + "RECEIVING" + "-"*32)
					new_frame.show()
				if new_frame.type == h2.H2DataFrame.type_id and new_frame.payload:
					response_data += new_frame.payload.data
					if 'ES' in new_frame.flags:
						break
				elif new_frame.type == h2.H2HeadersFrame.type_id and new_frame.payload:
					status_code_in_response = False
					for header in new_frame.hdrs:
						if 'index' in dir(header):
							index = int(header.index)
							if index >= 8 and index <= 14:
								status_code = bytes(h2.HPackHdrTable()._static_entries[index])
								status_codes.append(status_code)
					if 'ES' in new_frame.flags:
						break
				elif not isinstance(new_frame, type(None)):
					if 'ES' in new_frame.flags or new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id:
						if new_frame.type == h2.H2ResetFrame.type_id or new_frame.type == h2.H2GoAwayFrame.type_id:
							error_code = str(new_frame.error).encode()
							error_codes.append(h2.H2ErrorCodes.literal[new_frame.getfieldval('error')].encode())
						break
			except Exception as e:
				_print_exception(["seed="+str(self.seed), "host="+str(self.target_addr)])
				import time
				time.sleep(1)
				new_frame = None

		return b'response-code: ' + b','.join(status_codes) + b'\r\nerror: ' + b','.join(error_codes) + b'\r\nhost_header: ' + self.host_header.encode() + b'\r\n\r\n' + response_data 

if __name__ == '__main__':
    h2client = H2Client()
    h2client.send(argv[1], argv[2])
