#!/bin/bash
#
# Copyright (C) 2017 XYSec Labs (engineering@apppknox.com)
#
# Distributed under terms of the MIT license.
#

rm -rf dist/
python setup.py sdist
twine upload dist/*
