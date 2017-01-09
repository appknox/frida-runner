#!/usr/bin/env python

from setuptools import setup

setup(
    name='frida-runner',
    description='A Stupid CLI script to run Frida on a device',
    url='https://github.com/appknox/frida-runner',
    version='0.2.0',
    py_modules=['frida_runner'],
    author='XYSec Labs',
    author_email='engineering@appknox.com',
    install_requires=[
        'Click',
        'frida',
    ],
    entry_points='''
        [console_scripts]
        frida-runner=frida_runner:frida_runner
    ''',
)
