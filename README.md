
### Examples

```bash
./spray-out-there.py urls.txt
./spray-out-there.py http://site.foo/admin
./spray-out-there.py urls.txt -u john@company -p 1234
./spray-out-there.py http://site.bar/login -U users.txt -p abc123
./spray-out-there.py urls.txt -u root -P passwords.txt
assetfinder example.com | httprobe | ./spray-out-there.py
```

### Arguments
```
  -u user                 user
  -p pass                 password
  -U file                 user file
  -P file                 password file
  -o name                 output files prefix
  --filter {auto,yes,no}  Filter urls for certain keywords before logins search
```