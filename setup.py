"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
"""

from setuptools import setup # Always prefer setuptools over distutils
from codecs import open # To use a consistent encoding
from os import path


def read_long_description():
    this_directory = path.abspath(path.dirname(__file__))
    with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
        return f.read()


setup(
    name='django-basicauthly',

    # Versions should comply with PEP440.
    version='1.0.0a0',

    description='A module providing basic authentication support for Django',
    long_description=read_long_description(),

    # The project's main homepage:
    url='https://github.com/matt-chalmers/django-basicauthly',

    # Author details:
    author='Matt Chalmers',
    author_email='matt@barefootnomads.com',

    # Choose your license:
    license='MIT',

    # Classify the project:
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here.
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],

    # What does your project relate to?
    keywords='security authentication django basicauth',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=['basicauthly'],

    # Alternatively, if you want to distribute just a my_module.py, uncomment
    # this:
    #   py_modules=["my_module"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[
    ],

    setup_requires=['pytest-runner'],

    tests_require=[
        'pytest-cov>=2.3.1',
        'pytest-timeout>=1.0.0',
        'pytest>=3.0.2'
    ],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax:
    # $ pip install -e .[dev,test]
    extras_require={
        # 'dev': ['check-manifest'],
        # 'test': [],
    },
    
    use_2to3=True,
)