from typing import Callable

from .ctxt import EarlyCtxt, Ctxt
from .composition import Composition

def Middleware(Ctxt: type) -> type:
	return Callable[[Ctxt,Composition(Ctxt)],None]