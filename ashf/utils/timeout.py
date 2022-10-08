from functools import partial

from ..ashf import EarlyCtxt, Composition, Middleware

def _timeout(context: EarlyCtxt, child: Composition(EarlyCtxt), timeout: float):
	context.conn.settimeout(timeout)
	
	if child is not None:
		child(context)

def timeout(timeout: float) -> Middleware(EarlyCtxt):
	return partial(_timeout, timeout=timeout)
