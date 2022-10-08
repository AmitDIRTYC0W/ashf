class Rspn:
	def __init__(
		self,
		body: bytes=b'',
		status_code: int=418,
		reason_phrase: str="I'm a teapot",
		headers: dict[bytes, bytes]={}
	):
		self.body = body
		self.status_code = status_code
		self.reason_phrase = reason_phrase
		self.headers = headers

	def __str__(self) -> str:
		headers = '\nHeaders:\n\t' + '\n\t'.join({str(h) for h in self.headers.items()})
		body = '\n' + f'Body: {self.body}'
		return f'Response ({self.status_code} {self.reason_phrase}).' + headers + body

	def encode(self) -> bytes:
		status_line = f'HTTP/2 {self.status_code} {self.reason_phrase}'.encode() + b'\r\n'
		headers = b'\r\n'.join({name + b': ' + value for name, value in self.headers.items() if value is not None}) + b'\r\n'
		return status_line + headers + b'\r\n' + self.body
