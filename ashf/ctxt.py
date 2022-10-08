from socket import socket

from .rqst import Rqst
from .rspn import Rspn

class EarlyCtxt:
	def __init__(self, conn: socket, client_address: tuple[str, int]):
		self.conn = conn
		self.client_address = client_address

class Ctxt:
	def __init__(self, request: Rqst, response: Rspn):
		self.request = request
		self.response = response
