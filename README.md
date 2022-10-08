# ashf
Ashf (Amit's Stupid HTTP Framework) is a minimal HTTP server I built for educational purposes (my class).

## Features
* written in pure Python
* Koa.js-like philosophy
* Very, very simple
* Gzip content-encoding support
* Proven robust using Google's [Atheris](https://github.com/google/atheris) fuzzer

## Example Application

```python
import re
import ashf

# Define error pages Router requires.
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

# Define two routes.
def calculate_next(context: ashf.Ctxt, match: re.Match):
	'''
	A route that responds no + 1, where no is a GET parameter.
	'''
	try:
		no = int(context.request.parameters[b'no'])

		context.response.body = str(no + 1).encode()
		context.response.status_code = 200
		context.response.reason_phrase = b'OK'
	except:
		context.response.body = b'<html><head><title>Bad Request</title></head><body><h2>Error: Bad Request</h2></body></html>'
		context.response.status_code = 400
		context.response.reason_phrase = b'Bad Request'

def index(context: ashf.Ctxt, match: re.Match):
	'''
	A route that responds with the main page.
	'''
	context.response.body = b'<html><head><title>hello</title></head><body>Hi!</body></html>'
	context.response.status_code = 200
	context.response.reason_phrase = b'OK'

# Creatine a router, a middleware that returns different routes (pages)
# according to the request method and path.
router = ashf.utils.Router(error_404, error_405, error_500)
router.use(b'GET', b'\\/', index)
router.use(b'GET', b'\\/calculate-next', calculate_next)

# Initialise a new Ashf application.
app = ashf.Ashf()

# early_use appends functions (e.g. early middleware) that execute on new
# sockets. Here, we utilise it to set a timeout to all sockets.
app.early_use(ashf.utils.timeout(0.1))

# use appends middleware to the applicaiton. Each middleware will be executed
# one-by-one to process a request and form a response.
app.use(router)
app.use(ashf.utils.content_encode)
app.use(ashf.utils.content_length)

# Compile app. Internally, Ashf combines all the middleware together to ensure
# fast execution \m/ You must call it before starting the application.
app.compile()

# Start the server.
print(f'Listening on http://127.0.0.1:8080')
app.listen(port=8080)
```
