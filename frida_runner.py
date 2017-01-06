#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# vim: fenc=utf-8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

'''
File name: frida_runner.py
Author: dhilipsiva <dhilipsiva@gmail.com>
Date created: 2016-06-29
'''

from __future__ import print_function
from json import loads

import click
import frida
import sys

DEVICE_ID_PLACEHOLDER = '%s'
SCRIPT_WRAPPER = '''
(function(){
  var sendData = function (data) {
    payload = {
      'script_name': '%(script_name)s',
      'device_id': %(device_id)s,
      'data': data
    };
    send(JSON.stringify(payload));
  }
  try {
  /******************** START ********************/
    %(content)s
  /********************* END *********************/
  } catch (e) {
    var data = {'error': true, 'script': '%(script_name)s', 'stack': e.stack};
    send(JSON.stringify(data));
  }
})();
'''


def _print_with_line_no(text):
    '''
    docstring for _print_with_line_no
    '''
    for i, line in enumerate(text.split('\n')):
        line_no = i + 1
        print('{:>3}'.format(line_no), '|', line)
    print(' ')


def on_message(message, data):
    if 'payload' in message:
        try:
            payload = loads(message['payload'])
            for key in payload:
                print(key, ':', payload[key])
        except:
            print(message)
    else:
        print(message)
    print(' ')


@click.command()
@click.argument('app_name')
@click.argument('script_name')
@click.option('-v', '--verbose', count=True)
def frida_runner(app_name, script_name, verbose):
    '''
    Attach a Frida script to a running app
    '''
    try:
        content = open(script_name, 'r').read()

        device_id = DEVICE_ID_PLACEHOLDER
        script_text = SCRIPT_WRAPPER % locals()
        script_text = script_text % 1

        session = frida.get_usb_device().attach(app_name)
        script = session.create_script(script_text)

        if verbose:
            _print_with_line_no(script_text)

        script.on('message', on_message)
        script.load()
        sys.stdin.read()

    except Exception as e:
        print(e)
