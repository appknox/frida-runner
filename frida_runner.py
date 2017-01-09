#!/usr/bin/env python
#
# Copyright (c) 2017 XYSec Labs
# Distributed under terms of the MIT license
#

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
@click.option(
    '-v', '--verbose', is_flag=True, help='Print full script before attaching')
@click.option(
    '-H', '--host', type=str, help='Run on remote device at TEXT')
def frida_runner(app_name, script_name, verbose, host):
    """
    Attach Frida script to an app running on a device
    """
    try:
        content = open(script_name, 'r').read()

        device_id = DEVICE_ID_PLACEHOLDER
        script_text = SCRIPT_WRAPPER % locals()
        script_text = script_text % 1

        if verbose:
            _print_with_line_no(script_text)

        print('Starting session...')
        if host:
            remote_device = frida.get_device_manager().add_remote_device(host)
            session = remote_device.attach(app_name)
        else:
            session = frida.get_usb_device().attach(app_name)
        script = session.create_script(script_text)

        script.on('message', on_message)
        script.load()

        print('Connected')
        sys.stdin.read()

    except Exception as e:
        print(e)
