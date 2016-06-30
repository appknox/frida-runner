#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# vim: fenc=utf-8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
#

"""
File name: frida_runner.py
Author: dhilipsiva <dhilipsiva@gmail.com>
Date created: 2016-06-29
"""

import click

import frida
import sys

SCRIPT_WRAPPER = """
(function(){
  var sendData = function (message) {
    send(%(file_name)s, message);
  }
%(content)s
})();
"""


def on_message(message, data):
    print("Message: ", message)
    print("Data: ", data)
    print("==================================================================")


@click.command()
@click.argument('file_name')
@click.argument('app_name')
def frida_runner(file_name, app_name):
    """
    docstring for setup
    """
    content = open(file_name, "r").read()
    script_text = SCRIPT_WRAPPER % locals()
    print(script_text)
    session = frida.get_usb_device().attach(app_name)
    script = session.create_script(script_text)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
