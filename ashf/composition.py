from typing import Callable

def Composition(Ctxt: type) -> type:
	return Callable[[Ctxt],None]
