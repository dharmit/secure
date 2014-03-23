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


def check_for_failed_password(list_of_readlines):
    l = list_of_readlines
    for i in range(len(l)):
        #if has_failed_password_msg(l[i]) == True:
        if ' '.join(l[i].split(' ')[5:9]) == 'Failed password for root':
            print l[i]
            # write code to parse this line containing details of break-in
            # attempt. Also check db for existing events and ignore already
            # stored events. Check only for new events.
        else:
            continue


def scan_var_log_secure():
    global MTIME
    new_MTIME = os.path.getmtime("/var/log/secure")
    if MTIME == new_MTIME:
        return
    else:
        list_of_readlines = []
        try:
            with open('/var/log/secure') as f:
                list_of_readlines = f.readlines()
                check_for_failed_password(list_of_readlines)
        except IOError as e:
            print "You do not have enough permissions to access the file.\n" \
                  "Run the program as sudo or root user and try again."
            sys.exit()

        #print "new_MTIME = %f" % new_MTIME
        MTIME = new_MTIME
    return


def main():
    while 1:
        scan_var_log_secure()
        time.sleep(5)


if __name__ == "__main__":
    try:
        MTIME = os.path.getmtime("/var/log/secure")
    except os.error as e:
        print '/var/log/secure does not exist. Make sure the file exists and '\
              'try again later.'
        sys.exit()
    sys.exit(main())
