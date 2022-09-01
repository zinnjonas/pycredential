# pycredential

The goal of the project is to store user credentials in a file encrypted. So other applications can make use of the
credentials and do not need to store them as plain text or as global environment variables.

## How to use the module

This will generate a new credential file and a key file and read the credentials back with the key file.

```python
import os
from pycredential.credentials import Credentials

cred = Credentials()
key_file = "secret.key"
user_data = "user.cred"

if not os.path.exists(user_data):
    cred.ask_and_store(user_data, key_file=key_file)   
print(cred.load_user_data(user_data, key_file=key_file))
```

## Dependencies

This project makes use of the pycryptodomex module.

`pip install pycryptodomex` or
`pip install -r dependencies.txt`
