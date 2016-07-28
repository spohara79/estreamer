from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group()
    raise RuntimeError("Unable to find version string.")

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='estreamer',
    version=find_version('estreamer', '__init__.py',
    description='SourceFire eStream client Python library',
    long_description=long_description,
    url='https://github.com/spohara79/estreamer/',
    author="Sean O'Hara",
    author_email='spohara@gmail.com',
    license='Apache Software License 2.0',
    zip_safe=False,
    packages=['estreamer']
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='sample setuptools development',
    install_requires=['pyOpenSSL>=0.15.1'],
)
