import gzip

from ..ashf import Ctxt, Composition, Middleware

def content_encode(context: Ctxt, child: Composition(Ctxt)):
	if b'gzip' in context.request.headers['accept-encoding'].split(b', '):
		context.response.body = gzip.compress(context.response.body)
		context.response.headers[b'content-encoding'] = b'gzip'
	
	if child is not None:
		child(context)
