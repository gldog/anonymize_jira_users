#!/usr/bin/env python3

# Copyright 2020 Johannes Heger
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DIRECTORY_ATTRIBUTES = [
    'Benutzername',
    'Vollst',
    'Konto aktiv',
    'Konto abgelaufen'
]

log = logging.getLogger()
logging.basicConfig(level=logging.WARNING)
log.handlers[0].setFormatter(logging.Formatter('%(asctime)s:%(levelname)s: %(message)s'))
numeric_level = getattr(logging, 'DEBUG', None)
log.setLevel(numeric_level)

# net_binary_name = '/Users/jo/atlas/prj/anonymize_jira_users/net_mock.py'
net_binary_name = 'net'


def read_user_names_from_infile(file_name):
    user_names = []
    with open(file_name, 'r') as f:
        infile = f.read()
        lines = re.split('[\n\r]+', infile)
        for line in lines:
            line = line.strip()
            # Skip comment lines.
            if line and not line.startswith('#'):
                user_name = line
                user_names.append(user_name)
    return user_names


def read_ad_user_data_from_file(filename):
    with open(filename, 'r', encoding=None) as f:
        infile = f.read()
        return infile


def parse_ad_user_data(user_data):
    lines = re.split(r'[\n\r]+', user_data)
    user_properties = {}
    for line in lines:
        line = line.strip()
        for da in DIRECTORY_ATTRIBUTES:
            if line.startswith(da):
                parts = re.split(r'\s{2,}', line)
                user_properties[parts[0]] = parts[1]
    return user_properties


def get_ad_data_for_user(user_name):
    cmd = '{} user {} /domain'.format(net_binary_name, user_name)
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # result contains: returncode, stderr, stdout
    return result


def main():
    print("getpreferredencoding {}, getfilesystemencoding {}".format(locale.getpreferredencoding(),
                                                                     sys.getfilesystemencoding()))
    in_file_name = sys.argv[1]
    user_names = read_user_names_from_infile(in_file_name)
    log.info("User-names {}".format(user_names))
    lines = []
    for user_name in user_names:
        # log.info("User {}".format(user_name))
        net_result = get_ad_data_for_user(user_name)
        if net_result.returncode == 0:
            # user_properties = parse_ad_user_data(net_result.stdout.decode('utf-8'))
            decoded_stdout = net_result.stdout.decode('Latin-1')
            user_properties = parse_ad_user_data(decoded_stdout)
            # log.debug("user_properties {}".format(user_properties))
            line_parts = []
            for k, v in user_properties.items():
                line_parts.append("{}: {}".format(k, v))
            line = '; '.join(line_parts)
            # The user has been found in the directory. It is likely they shall not be anonymized.
            log.info("User {}: {}".format(user_name, line))
            lines.append('# {}'.format(line))
            lines.append("#{}".format(user_name))
        else:
            # The user not has been found in the directory. It is likely they shall be anonymized.
            line = "Not in directory"
            log.info("User {}: {}".format(user_name, line))
            lines.append('# {}'.format(line))
            lines.append("{}".format(user_name))
        lines.append("")

    stem_name = Path(in_file_name).stem
    out_file_name = "{}_assessed.txt".format(stem_name)
    with open(out_file_name, 'w', encoding='utf-8') as f:
        # Create a date/time-string, but remove the nit-picky microseconds.
        date_string = "{}".format(datetime.now()).split('.')[0]
        f.write("# File generated at {}\n\n".format(date_string))
        f.write('\n'.join(lines))


if __name__ == '__main__':
    main()
