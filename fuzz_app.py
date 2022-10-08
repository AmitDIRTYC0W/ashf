import sys
import atheris

import ashf
# with atheris.instrument_imports():
# 	import ashf

def error_404(context: ashf.Ctxt):
	context.response.body = b'<html><head><title>Not Found</title></head><body><h2>Error: Not Found</h2></body></html>'
	context.response.status_code = 404
	context.response.reason_phrase = b'Not Found'

def error_405(context: ashf.Ctxt):
	context.response.body = b'<html><head><title>Method Not Allowed</title></head><body><h2>Error: Method Not Allowed</h2></body></html>'
	context.response.status_code = 405
	context.response.reason_phrase = b'Method Not Allowed'

def error_500(context: ashf.Ctxt):
	context.response.body = b'<html><head><title>Internal Server Error</title></head><body><h2>Error: Internal Server Error</h2></body></html>'
	context.response.status_code = 500
	context.response.reason_phrase = b'Internal Server Error'

def calculate_next(context: ashf.Ctxt, match):
	try:
		num = int(context.request.parameters[b'num'])

		context.response.body = str(num + 1).encode()
		context.response.status_code = 200
		context.response.reason_phrase = b'OK'
	except:
		context.response.body = b'<html><head><title>Bad Request</title></head><body><h2>Error: Bad Request</h2></body></html>'
		context.response.status_code = 400
		context.response.reason_phrase = b'Bad Request'

def index(context: ashf.Ctxt, match):
	context.response.body = b'<html><head><title>hello</title></head><body>Hi!</body></html>'
	context.response.status_code = 200
	context.response.reason_phrase = b'OK'

router = ashf.utils.Router(error_404, error_405, error_500)
router.use(b'GET', b'\\/', index)
router.use(b'GET', b'\\/calculate-next', calculate_next)

app = ashf.Ashf()
app.use(router)
app.use(ashf.utils.content_encode)
app.use(ashf.utils.content_length)
app.compile()

atheris.instrument_all()
atheris.Setup(sys.argv, app._answer)
atheris.Fuzz()