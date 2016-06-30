#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# vim: fenc=utf-8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
#

"""
File name: setup.py
Author: dhilipsiva <dhilipsiva@gmail.com>
Date created: 2016-06-29
"""

from setuptools import setup

setup(
    name='frida-runner',
    description="A Stupid CLI script to run Frida on iOS or Android",
    url='https://github.com/appknox/frida-runner',
    version='0.1.0',
    py_modules=['frida_runner'],
    author='dhilipsiva',
    author_email='dhilipsiva@gmail.com',
    install_requires=[
        'Click',
        'frida',
    ],
    entry_points='''
        [console_scripts]
        frida-runner=frida_runner:frida_runner
    ''',
)
