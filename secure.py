"""secure.py checks /var/log/secure for new occurrences of "Failed password"
mesages and sends a mail for new break-in attempts on the system. I also
plan to add a feature to drop any traffic from an IP that has attempted to
break-in more than configured times."""

import os
import sqlite3
import sys
import time

# initially set to 0, MTIME keeps a track of the latest modification time for
# /var/log/secure file

MTIME = 0


def fetch_last_from_db():
    """ Code in this function will fetch the last entry in the db. This is
    is helpful in figuring out if the data parsed by the program is newer
    than the existing db entries."""
    pass


def insert_into_db(l):
    """ This funtion inserts into the database the break-in attempts that are
    newer than the last one as returned by fetch_last_from_db() function"""
    pass


def new_attempts_from_last():
    """This function will determine the break-in attempts newer than the last
    break-in attempt"""
    pass


def clean_for_db(l):
    """ This function cleans the log message containing "Failed password for
    root" to reduce it only upto the values that need to be entered into the
    db. Values needed for db - month(0), date(1), time(2), 
    remote_ip_address(10)"""
    pass

def database_operations(l):
    """ This function takes a list of break-in attempt log messages that our
    program found from /var/log/secure and then performs database operations
    on it like - finding last break-in attempt's details, ensure to insert
    and notify only for attempts newer than last attempt, insert these new
    entries into the database"""
    pass

def check_for_failed_password(list_of_readlines):
    l = list_of_readlines
    for i in range(len(l)):
        #if has_failed_password_msg(l[i]) == True:
        if ' '.join(l[i].split(' ')[3:7]) == 'Failed password for root':
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
