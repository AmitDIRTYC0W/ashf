from typing import Callable
from re import Pattern, Match, compile
import logging

from ..ashf import Ctxt, Composition

Route = Callable[[Ctxt,Match],None]

class Router:
	def __init__(
		self,
		error_404: Route,
		error_405: Route,
		error_500: Route,
		routes: dict[bytes,dict[Pattern,Route]]={}
	):
		self.error_404 = error_404
		self.error_405 = error_405
		self.error_500 = error_500
		self.routes = routes

	def __call__(self, context: Ctxt, child: Composition(Ctxt)):
		if context.request.method in self.routes:
			paths = self.routes[context.request.method]

			route, match = None, None
			for p, r in paths.items():
				match = p.fullmatch(context.request.path)

				if match:
					route = r
					break

			if match:
				try:
					route(context, match)
				except Exception as e:
					logging.error(e)
					self.error_500(context)
			else:
				self.error_404(context)
		else:
			self.error_405(context)

		if child is not None:
			child(context)

	def use(self, method: bytes, path: bytes, route: Route):
		pattern = compile(path)

		if method not in self.routes:
			self.routes[method] = {pattern: route}
		else:
			self.routes[method][pattern] = route