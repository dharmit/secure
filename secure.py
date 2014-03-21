# secure.py checks /var/log/secure for new occurrences of "Failed password" 
# mesages and sends a mail for new break-in attempts on the system. I also
# plan to add a feature to drop any traffic from an IP that has attempted to
# break-in more than configured times.

import os
import sys
import time

# initially set to 0, MTIME keeps a track of the latest modification time for
# /var/log/secure file

MTIME = 0

def scan_var_log_secure():
    global MTIME
    new_MTIME = os.path.getmtime("/var/log/secure")
    if MTIME == new_MTIME:
        print "MTIME = %f" % MTIME
        return
    else:
        # code to scan new occurrences.
        print "new_MTIME = %f" % new_MTIME
        MTIME = new_MTIME
    return


def main():
    while 1:
        scan_var_log_secure()
        time.sleep(60)
    print MTIME


if __name__ == "__main__":
    try:
        MTIME = os.path.getmtime("/var/log/secure")
    except os.error as e:
        print '/var/log/secure does not exist. Make sure the file exists and ' \
                'try again later.'
        sys.exit()
    sys.exit(main())
