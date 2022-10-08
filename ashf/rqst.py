class Rqst:
	def __init__(
		self,
		method: bytes,
		path: bytes,
		parameters: dict[bytes, bytes],
		http_version: bytes,
		headers: dict[str, bytes],
		body: bytes,
		is_invalid: bool=False
	):
		self.method = method
		self.path = path
		self.parameters = parameters
		self.http_version = http_version
		self.headers = headers
		self.body = body
		self.is_invalid = is_invalid

	def __str__(self) -> str:
		parameters = '\nParameters:\n\t' + '\n\t'.join({str(p) for p in self.parameters.items()})
		headers = '\nHeaders:\n\t' + '\n\t'.join({str(h) for h in self.headers.items()})
		body = '\n' + f'Body: {self.body}'
		return f'A {self.method.decode()} request to {self.path.decode()}.' + parameters + headers + body

	def parse(plain: bytes):
		request = Rqst(None, None, {}, None, {}, None, False)

		parts = plain.split(b'\r\n\r\n', 2)
		if len(parts) == 2:
			lines, request.body = parts
		else:
			lines = parts[0]
			request.body = b''

		lines = lines.split(b'\r\n')

		try:
			request.method, resource, request.version = lines[0].split(b' ', 2)
			resource = resource.split(b'?', 1)
			if len(resource) == 2:
				request.path, parameters_text = resource
				for parameter_text in parameters_text.split(b'&'):
					name, value = parameter_text.split(b'=', 1)
					request.parameters[name] = value
			else:
				request.path = resource[0]
				request.parameters = {}
		except ValueError:
			request.is_invalid = True

		headers_text = lines[1:]
		for header_text in headers_text:
			try:
				name, value = header_text.split(b': ')
			except:
				request.is_invalid = True
				continue

			try:
				name = name.decode().lstrip().lower()
			except:
				request.is_invalid = True
				continue

			request.headers[name] = value

		return request