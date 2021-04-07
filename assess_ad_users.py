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
import locale
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Download it from: http://www.joeware.net/freetools/tools/adfind/
AD_QUERY_TOOL = 'adfind'
ENCODING = 'latin-1'

DIRECTORY_ATTRIBUTES = [
    'cn',
    'mail',
    'accountExpires'
]


def format_ldap_timestamp(timestamp):
    """
    This function is copied from https://gist.github.com/caot/f57fbf419d6b37d53f6f4a525942cafc.
    About "Account-Expires attribute":
        https://docs.microsoft.com/en-us/windows/win32/adschema/a-accountexpires
    "Convert 18-digit LDAP/FILETIME timestamps to human-readable date":
        https://www.epochconverter.com/ldap
    """
    timestamp = float(timestamp)
    seconds_since_epoch = timestamp / 10 ** 7
    loc_dt = datetime.fromtimestamp(seconds_since_epoch)
    loc_dt -= timedelta(days=(1970 - 1601) * 365 + 89)
    return loc_dt


def read_user_names_from_file(file_name):
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


def count_by_ldap_filter(ldap_filter):
    cmd = [AD_QUERY_TOOL, '-f', ldap_filter, '-c']
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    decoded_stdout = r.stdout.decode(ENCODING)
    # Search a line of format:
    #   "1 Objects returned"
    m = re.search(r'^\s*([0-9]+)\s+Objects returned', decoded_stdout, re.MULTILINE)
    return int(m.group(1)) if m else 0


def get_by_ldap_filter(ldap_filter):
    cmd = [AD_QUERY_TOOL, '-f', ldap_filter]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    return r.stdout.decode(ENCODING)


def get_ad_properties_for_san(sam_account_name, ad_attributes=None):
    decoded_stdout = get_by_ldap_filter(f'samAccountName={sam_account_name}')
    lines = re.split(r'[\n\r]+', decoded_stdout)
    user_properties = {}
    for line in lines:
        line = line.strip()
        # print(f"LINE: {line}")
        ad_attributes = ad_attributes if ad_attributes else DIRECTORY_ATTRIBUTES
        for da in ad_attributes:
            # The lines are in the following format:
            # >cn: The Animal
            # >mail: animal@example.com
            if line.startswith(f'>{da}:'):
                line = line.replace(f'>{da}: ', '')
                if da == 'accountExpires':
                    # The date is given as "18-digit LDAP/FILETIME timestamps". It is not always
                    # set to a real date. Sometimes it is set to a "marker"-date indicating a
                    # date far in the future.
                    # Unfortunately, the format_ldap_timestamp() can't convert timestamps in higher
                    # ranges. The magic number "13" limits the timestamps to those around "now":
                    # 130000000000000000: 14. December 2012 23:06:40
                    # 139999999999999999: 23. August 2044 00:53:20
                    # If not in range, the timestamp is printed to the file rather than the
                    # human readable format.
                    if line.startswith('13'):
                        line = format_ldap_timestamp(line)
                user_properties[da] = line
    return user_properties


def print_usage():
    print(f"Usage: {os.path.basename(__file__)} <user-name-file>")


def main():
    print("Always call me in a Windows CMD-shell.")
    if len(sys.argv) != 2:
        print_usage()
        sys.exit(1)
    print(f"getpreferredencoding {locale.getpreferredencoding()}, getfilesystemencoding {sys.getfilesystemencoding()}")
    user_name_file = sys.argv[1]
    user_names = read_user_names_from_file(user_name_file)
    print(f"User-names ({len(user_names)}): {user_names}")
    lines = []
    for user_name in user_names:
        # log.info(f"User {user_name}")
        # Expect 0 or 1, as samAccountName is expected as unique.
        if count_by_ldap_filter(f'sAMAccountName={user_name}'):
            # The user has been found in the directory. It is likely they shall not be anonymized.
            ad_properties = get_ad_properties_for_san(user_name)
            line_parts = []
            for k, v in ad_properties.items():
                line_parts.append(f'{k}: {v}')
            line = '; '.join(line_parts)
            print(f"User {user_name}: {line}")
            lines.append(f'# {line}')

            # Is there any other dataset with that user-name 'cn'? This could mean, the same user has
            # multiple accounts. Let the caller know.
            ldap_filter = f'(&(cn={ad_properties["cn"]})(!(sAMAccountName={user_name})))'
            num_others = count_by_ldap_filter(ldap_filter)
            # DBG: print(f":: ldap_filter {ldap_filter}; num_others {num_others}")
            if num_others > 0:
                if num_others == 1:
                    count_phrase = 'is 1 more user'
                else:
                    count_phrase = f'are {num_others} more users'
                message = f'# NOTE: There {count_phrase} in AD with cn={ad_properties["cn"]}'
                lines.append(message)
                print(f"User {user_name}: {message}")
                cmd = f'{AD_QUERY_TOOL} -f "cn={ad_properties["cn"]}"'
                message = f"#  To get the data of all users including {user_name}, type '{cmd}'"
                lines.append(message)
                print(f"User {user_name}: {message}")
            lines.append(f'#{user_name}')
        else:
            # The user not has been found in the directory. It is likely they shall be anonymized.
            user_info = 'Not found in directory'
            print(f'User {user_name}: {user_info}')
            lines.append(f'# {user_info}')
            lines.append(f"{user_name}")
        lines.append('')

    stem_name = Path(user_name_file).stem
    out_file_name = f'{stem_name}_assessed.cfg'
    with open(out_file_name, 'w', encoding='utf-8') as f:
        # Create a date/time-string, but remove the nit-picky microseconds.
        date_string = str(datetime.now()).split('.')[0]
        f.write(f'# File generated at {date_string}\n\n')
        f.write('\n'.join(lines))


if __name__ == '__main__':
    main()
