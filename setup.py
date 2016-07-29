from setuptools import setup, find_packages
import codecs
import os
import re

here = os.path.abspath(os.path.dirname(__file__))

def read(*parts):
    return codecs.open(os.path.join(here, *parts), 'r').read()

def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

long_description = read('README.rst')

setup(
    name='estreamer',
    version=find_version('estreamer', '__init__.py'),
    description='SourceFire eStream client Python library',
    long_description=long_description,
    url='https://github.com/spohara79/estreamer/',
    author="Sean O'Hara",
    author_email='spohara@gmail.com',
    license='Apache Software License',
    zip_safe=False,
    packages=['estreamer'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='sourcefire estreamer',
    install_requires=['pyOpenSSL>=0.15.1', 'six>=1.10.0'],
)
