#!/usr/bin/env python
"""
Packaging for the riscos_disassemble package.
"""

from distutils.core import setup
import setuptools  # noqa

from os import path
# io.open is needed for projects that support Python 2.7
# It ensures open() defaults to text mode with universal newlines,
# and accepts an argument to specify the text encoding
# Python 3 only projects can skip this import
from io import open

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name = 'riscos-disassemble',
    packages = ['riscos_disassemble'],
    version = '0.1.0',
    license='MIT',
    description = 'Disassemble ARM and Thumb files like RISC OS',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    author = 'Charles Ferguson',
    author_email = 'gerph@gerph.org',
    url = 'https://github.com/gerph/riscos-disassemble-python',
    keywords = ['disassemble', 'arm', 'riscos'],
    entry_points={ 'console_scripts': ['riscos-dumpi = riscos_disassemble.__main__:main'] },
    install_requires= [
            'capstone',
        ],
    classifiers= [
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            "Operating System :: OS Independent",
        ],
    python_requires='>=2.7',
)
