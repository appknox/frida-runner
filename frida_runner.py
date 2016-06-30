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

from json import loads

import click

import frida
import sys

SCRIPT_WRAPPER = """
(function(){
  var sendData = function (data) {
    data["file_name"] = "%(file_name)s"
    send(JSON.stringify(data));
  }
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~START~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
%(content)s
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~END~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
})();
"""


def _print_with_line_no(text):
    """
    docstring for _print_with_line_no
    """
    for i, line in enumerate(text.split("\n")):
        line_no = i + 1
        print('{:<3}'.format(line_no), "|", line)
    print("==================================================================")


def on_message(message, data):
    if 'payload' in message:
        message = loads(message['payload'])
        for key in message:
            print(key, ":", message[key])
    else:
        print(message)
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
    _print_with_line_no(script_text)
    session = frida.get_usb_device().attach(app_name)
    script = session.create_script(script_text)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
