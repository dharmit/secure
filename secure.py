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
LASTROWID = 0

def database_exists():
    return os.path.exists("var_log_secure.db") #and os.path.exists("count.db")


def create_database():
    """We will create two databases. One for logging the details of attempt
    like date & ip while another for keeping a track of number of attempts made
    from a particular IP. In future we plan to drop all packets coming from an
    IP that has made X (say, 5) attempts using firewall rules.
    """
    try:
        db = sqlite3.connect("var_log_secure.db")
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS
                       attempts(id INTEGER PRIMARY KEY, hour INTEGER, minute
                       INTEGER, second INTEGER, day INTEGER, month INTEGER,
                       year INTEGER, ip TEXT)''')
        db.commit()
    except Exception as e:
        raise e
    finally: db.close()


def fetch_last_from_db():
    """ Code in this function will fetch the last entry in the db. This is
    is helpful in figuring out if the data parsed by the program is newer
    than the existing db entries."""
    global LASTROWID
    if LASTROWID:
        try:
            db = sqlite3.connect("var_log_secure.db")
            cursor = db.cursor()
            cursor.execute('select * from attempts where id=?',(LASTROWID,))
            data = cursor.fetchone()
            return data
        except Exception as e:
            raise e
        finally:
            db.close()
    return None


def insert_into_db(data):
    """ This funtion inserts into the database the break-in attempts that are
    newer than the last one as returned by fetch_last_from_db() function"""
    global LASTROWID
    day, month, year, hour, minute, second = data["day"], data["month"],\
                                             data["year"], data["hour"],\
                                             data["minute"], data["second"]
    user, ip = data["user"], data["ip"]
    try:
        db = sqlite3.connect("var_log_secure.db")
        cursor = db.cursor()
        cursor.execute("SELECT count(*) from attempts")
        LASTROWID = cursor.fetchone()[0]
        print "Lastrowid in try block, ", LASTROWID
    except Exception as e:
        raise e
    finally:
        db.close()

    last_record = fetch_last_from_db()

    print last_record

    try:
        db1 = sqlite3.connect("var_log_secure.db")
        cursor1 = db1.cursor()
        cursor1.execute("INSERT INTO attempts(hour, minute, second, day,\
                        month, year, ip) VALUES(?, ?, ?, ?, ?, ?, ?)", \
                        (hour, minute, second, day, month, year, ip))
        print LASTROWID
        db1.commit()
    except Exception as e:
        db1.rollback()
        raise e
    finally:
        db1.close()
        

def new_attempts_from_last():
    """This function will determine the break-in attempts newer than the last
    break-in attempt"""
    pass


def database_operations(date, msg):
    """ Initialy part of this code takes care of splitting 'msg' into chunks
    useful for dataabase. Next it calls various db related functions to insert
    the data or retrieve details of last known attempt."""

    time_of_attempt = msg[0].split('T')[1].split(':')
    time_of_attempt[2] = int(float(time_of_attempt[2].split('+')[0]))

    year, month, day = date[0], date[1], date[2]
    hour, minute, second = time_of_attempt[0], time_of_attempt[1],\
                           time_of_attempt[2]
    user, ip = msg[6], msg[8]
    data = {"year" : year, "month" : month, "day" : day, "ip" : ip, "user" :
            user, "hour" : hour, "minute" : minute, "second" : second}
    insert_into_db(data)


def check_for_failed_password(list_of_readlines):
    l = list_of_readlines
    for i in range(len(l)):
        if ' '.join(l[i].split(' ')[3:6]) == 'Failed password for':
            x = l[i].split('T')  # Temporary variable to fetch date.
            date = x[0].split('-')
            message = l[i].split(' ')
            database_operations(date, message)
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
    #return


def main():
    if not database_exists():
        create_database()
    while 1:
        scan_var_log_secure()
        time.sleep(5)
    sys.exit(1)

if __name__ == "__main__":
    if os.path.exists("/var/log/secure"):
        sys.exit(main())
    else:
        print '/var/log/secure does not exist. Make sure the file exists and '\
              'try again later.'
        sys.exit(1)
