import atheris
import sys

with atheris.instrument_imports():
	from ashf import Rqst

atheris.Setup(sys.argv, Rqst.parse)
atheris.Fuzz()