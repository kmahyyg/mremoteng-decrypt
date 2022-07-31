# mRemoteNG Decrypt

Use for Decrypt mRemoteNG v1.75+ Config. For v1.74 and lower, use Python version with `_legacy` suffix.

Usage: `java -jar <JAR FILE> <ENCRYPTED TEXT> [Custom Password]`

The custom password is in: `%appdata/mRemoteNg/<Most recently modified folder>/User.config`

## Build dependencies

org.apache.commons.codec

org.bouncycastle

## Python Script

Usage: `python3 mremoteng_decrypt.py [-f FILE | -s STRING] [-p CUSTOM_PASSWORD]`

## Where's the file?

Carefully check the page.
