Signal for Android backup decryption tool
=========================================

This repository contains an (unofficial) tool which decrypts backup files
produced by the [Signal](https://signal.org/) Android app.

What this tool is **not**:

* This tool does not export the backup data into a ready-to-use format, it
  simply decrypts the SQLite database and binary blobs within the backup file
  and leaves the rest up to you to work out.
* This tool does not support backup files produced by the iOS Signal app.
* This is not an official product from the Signal team. It depends on internal
  implementation details gleaned by reading the [source code of the Signal for
  Android app](https://github.com/signalapp/Signal-Android). While it appeared
  to work circa January 2021, this tool may break in the future.

For a [walk-through of the Signal for Android backup format, see this article
on my website](http://jhnet.co.uk/articles/signal_backups). If you just want to
get going; keep reading!


Dependencies
------------

This tool is designed to run under Python 3.7+.

You can install the required Python dependencies as follows:

    $ pip install -r requirements.txt

Optionally, you may rebuild the [Protocol
Buffer](https://developers.google.com/protocol-buffers) Python module:

    $ protoc -I=. --python_out=. Backups.proto


Usage
-----

Generate a backup using the Signal app (see the [Signal support
pages](https://support.signal.org/hc/en-us/articles/360007059752-Backup-and-Restore-Messages)
for details).  Be very careful to write down the generated passphrase
correctly.  If you have a large number of photographs and videos within any of
your groups the backup process can take several hours.

You can then decrypt the backup file as follows:

    $ python decrypt_backup.py path/to/signal.backup path/to/output/dir

The tool will prompt you for your backup passphrase (spaces are optional) and
then extract the backup file into the specified output directory.

The backup will be decrypted into the directory you specified. The extracted
files are organised as follows:

* `database.sqlite`: A dump of the [SQLite](https://www.sqlite.org) database
  used by the signal app. This database is home to all of backed up messages
  and metadata aside from media files. The contents of this database are
  implementation defined and it is up to you to work out how to extract the
  information you want.
* `preferences.json`: A JSON file containing the 'preference' data encoded by
  the backup. Despite the existance of this file, most application preferences
  are stored in the SQLite database.
* `key_value.json`: A JSON file containing the 'key-value' data encoded by
  the backup.
* `attachments/*.bin`: Binary files attached to messages sent or received (e.g.
  photos and videos). These are named based on their `unique_id` as used in the
  database. To infer the correct file extension you'll need to lookup the MIME
  type in the database or guess based on the contents of the file.
* `stickers/*.bin`: Binary files containing sticker graphics used in chats. See
  also: attachments.
* `avatars/*.bin`: Binary files containing avatars images given to contacts and
  groups. See also: attachments.

A final obvious warning: all decrypted files are...unencrypted(!). You should
make sure to only perform decryption on a trusted device backed by sufficiently
secure storage for your needs.
