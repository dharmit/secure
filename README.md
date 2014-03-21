secure
======

Python program that keeps an eye on `/var/log/secure` and reports "Failed password" attempts.

Features:
--------
* Checks the file `/var/log/secure` every minute for new occurrence of **Failed password** message(s).
* If new attempt is found, it stores details in the SQLite database.
* After adding details to the database, sends an e-mail to the configured address.
