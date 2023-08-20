#from setuptools import setup
from setuptools import Extension, setup
from Cython.Build import cythonize

ext_modules = [
    Extension(
        "tasks_vanity",
        ["tasks_vanity.pyx"],
        extra_compile_args=['-fopenmp'],
        extra_link_args=['-fopenmp'],
    )
]

setup(
    ext_modules = cythonize(['vanity.py', 'tasks_vanity.pyx', 'shared.pyx'], language_level = "3")
)