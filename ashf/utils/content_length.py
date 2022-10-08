import gzip

from ..ashf import Ctxt, Composition, Middleware

def content_length(context: Ctxt, child: Composition(Ctxt)):
	context.response.headers[b'content-length'] = str(len(context.response.body)).encode()
	
	if child is not None:
		child(context)
