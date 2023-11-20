import distutils.core
import Cython.Build
import numpy as np

distutils.core.setup(
    ext_modules = Cython.Build.cythonize("vectorized2.pyx"))