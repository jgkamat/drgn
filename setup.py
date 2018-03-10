#!/usr/bin/env python3

from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize


extensions = [
    Extension(
        name='drgn.dwarf',
        sources=[
            'drgn/dwarf.pyx',
        ],
    ),
    Extension(
        name='drgn.elf',
        sources=[
            'drgn/elf.pyx',
        ],
    ),
]

setup(
    name='drgn',
    ext_modules=cythonize(extensions),
)