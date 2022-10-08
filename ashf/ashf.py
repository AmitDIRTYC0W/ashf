from functools import partial
from typing import List, TypeVar
import socket

from .ctxt import EarlyCtxt, Ctxt
from .composition import Composition
from .middleware import Middleware
from .rqst import Rqst
from .rspn import Rspn

C = TypeVar('C', EarlyCtxt, Ctxt)

def _compose(middleware: List[Middleware(C)]) -> Composition(C):
	if len(middleware) > 1:
		return partial(middleware[0], child=_compose(middleware[1:]))
	else:
		return partial(middleware[0], child=None)

class Ashf:
	def __init__(self):
		self.early_middleware = []
		self.middleware = []

		self.early_composition = lambda _: None
		self.composition = lambda _: None

	def early_use(self, middleware: Middleware(EarlyCtxt)):
		self.early_middleware.append(middleware)

	def use(self, middleware: Middleware(Ctxt)):
		self.middleware.append(middleware)

	def compile(self):
		if len(self.early_middleware) != 0:
			self.early_composition = _compose(self.early_middleware)

		if len(self.early_middleware) != 0:
			self.composition = _compose(self.middleware)

	def _answer(self, data: bytes) -> bytes:
		context = Ctxt(Rqst.parse(data), Rspn())
		self.composition(context)
		return context.response.encode()

	def listen(self, address: str='127.0.0.1', port: int=80):
		# Listen to incoming TCP connections.
		with socket.socket() as s:
			s.bind((address, port))
			s.listen()

			while True:
				early_context = EarlyCtxt(*s.accept())
				self.early_composition(early_context)

				with early_context.conn:
					data = early_context.conn.recv(1024)

					if data is not None:
						early_context.conn.sendall(self._answer(data))
