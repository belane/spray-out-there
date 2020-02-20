
### Examples

```bash
python3 spray-out-there.py urls.txt
python3 spray-out-there.py http://site.foo/admin
python3 spray-out-there.py urls.txt -u john@local -p 1234
python3 spray-out-there.py http://site.bar/login -U users.txt -p abc123
python3 spray-out-there.py urls.txt -u root -P passwords.txt
```

### Arguments
```
  -u user        user
  -p pass        password
  -U file        user file
  -P file        password file
  -o name        output files prefix
  --filter-urls  Filter urls for certain keywords before search for logins
  ```