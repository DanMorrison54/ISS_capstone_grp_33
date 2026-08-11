# Phishing Risk Analyzer Extension

Our browser extension reads an opened Gmail message and sends the visible email information to the local Flask/BERT server.


## Features

- Reads sender, subject, and visible email body.

- Reads visible attachment filenames without opening or downloading files.

- Supports Gmail.

- Shows the phishing label, confidence, overall risk level, and reasons.

- Keeps manual fields available as backup.



## Attachment limitation

The extension checks attachment filename metadata only. It does NOT INSPECT FILE CONTENT and cannot guarantee that a file is safe or malicious.
