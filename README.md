# TON Connect

Inspired by: [ts ton-connect](https://github.com/tonkeeper/ton-connect) <br>
Implements: [📄 TON Connect Specification](https://github.com/tonkeeper/ton-connect/blob/main/TonConnectSpecification.md)

This software is provided "as is" without warranty of any kind.<br>
Do not use it in your production unless you know what you are doing.

The library has only been tested with Tonkeeper login.

## Installation
Run 'install' from the repository folder:
```bash
pip install .
```

## How to use on your server

Read the [specification](https://github.com/tonkeeper/ton-connect/blob/main/TonConnectSpecification.md) first.

Create an auth request for a user:
```python
import base64
import secrets

from ton_connect import AuthRequestOptions, AuthRequestOption, AuthRequest


# Generating a secret key (32 bytes long)
secret_key = base64.b64encode(secrets.token_bytes(32))

# Creating the auth request: 
options = AuthRequestOptions(
    image_url=...,
    return_url=...,
    callback_url=...,
    items=[
        AuthRequestOption(AuthRequestOption.Kind.OWNERSHIP, required=True)
    ]
)
req = AuthRequest.create(options, secret_key)  # 'data' parameter can be passed with your custom data

# Use 'result' to reply from your server
result = req.to_dict()
```

When you receive a callback request after the user has been authorized, 
you can check the wallet ownership like this:
```python
from ton_connect import AuthResponse


# Creating an auth response, where:
# - 'data' is taken from the request
# - 'secret_key' is your secret key from the previous step
res = AuthResponse.create_from_data(data, secret_key)
result = res.verify_ton_ownership(res.payload[0], res.client_id)

# True if the ownership has been verified
if result:
    # Extract the address and other data from the payload as simple as that:
    print(res.payload[0].address)
```

## Contacts

If you have any questions or suggestions, don't hesitate to open an issue or contact the developers at
stardust.skg@gmail.com.
