This script checks each user from a given file for existance in AD.

Call:

    python assess_ad_users.py inactive_users.cfg

The script writes the
new file `inactive_users_assessed.cfg`. This file is basically `inactive_users.cfg`. But
it is extended with data from AD. If a user is still in AD, the user is commented out.

Uses the Windows-binary `adfind.exe`. You can download it
from [AdFind](http://www.joeware.net/freetools/tools/adfind/)

From my experience, you should call the script in a Windows CMD-shell (not in e.g. a
Git-bash).


