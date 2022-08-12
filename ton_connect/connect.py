import base64
import json
import math
import time

from dataclasses import dataclass, asdict
from typing import List, Optional, Union

import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils

from .wallet import wallet_manager


@dataclass
class AuthRequestOption:
    class Kind:
        ADDRESS = 'ton-address'
        OWNERSHIP = 'ton-ownership'

    type: str
    required: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuthRequestOptions:
    image_url: str  # displayed to the user
    callback_url: str  # redirect url, auth response will be in "tonlogin" cgi
    return_url: str  # url to be shown in UI after callback_url answers 200 OK
    items: List[AuthRequestOption]

    return_serverless: bool = False  # "tonlogin" as anchor (after #)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuthRequest:
    protocol: str
    version: str
    session: str  # session public key
    session_payload: str  # arbitrary, must be returned from the client to the server
    options: AuthRequestOptions

    @classmethod
    def create(
            cls,
            options: AuthRequestOptions,
            static_secret: bytes,
            data: Optional[dict] = None,
            version: str = 'v1'
    ) -> 'AuthRequest':
        if not data:
            data = {}

        pk = nacl.public.PrivateKey.generate()

        session = bytes(pk.public_key)
        session_key = bytes(pk)

        return AuthRequest(
            protocol='ton-auth',
            version=version,

            session=base64.b64encode(session).decode(),
            session_payload=cls.pack_session_data(session_key, data, static_secret).decode(),
            options=options
        )

    @staticmethod
    def pack_session_data(session_key: bytes, session_data: dict, static_secret: bytes) -> bytes:
        session_expires = 5 * 60
        nonce_len = 24

        ts = int(time.time())
        exp = math.floor(ts + session_expires)
        nonce = nacl.utils.random(nonce_len)

        payload = json.dumps({
            'tonconnect': {
                'exp': exp,
                'sk': base64.b64encode(session_key).decode()
            },
            **{'data': session_data}
        })

        box = nacl.secret.SecretBox(static_secret)

        try:
            encrypted = box.encrypt(payload.encode(), nonce)
        except Exception:
            raise InvalidSessionPayloadException

        return base64.b64encode(encrypted)

    def to_dict(self) -> dict:
        return {
            'protocol': self.protocol,
            self.version: {
                'session': self.session,
                'session_payload': self.session_payload,
                **self.options.to_dict()
            }
        }


#


@dataclass
class OwnershipPayload:
    type: str
    wallet_version: str
    wallet_id: str
    signature: str
    address: str
    pubkey: str


@dataclass
class AddressPayload:
    type: str
    address: str


@dataclass
class AuthResponse:
    client_id: str
    session_data: dict
    payload: List[Union[OwnershipPayload, AddressPayload]]

    @classmethod
    def create_from_data(cls, data: dict, static_secret: bytes) -> 'AuthResponse':
        authenticator = base64.b64decode(data['authenticator'])
        client_id = base64.b64decode(data['client_id'])
        nonce = base64.b64decode(data['nonce'])
        session = cls.unpack_session_data(data['session_payload'], static_secret)

        box = nacl.public.Box(nacl.public.PrivateKey(session['sk']), nacl.public.PublicKey(client_id))

        try:
            decrypted = box.decrypt(authenticator, nonce)
        except Exception:
            raise InvalidPayloadException

        client_id = data['client_id']
        payload = json.loads(decrypted)

        return AuthResponse(
            client_id,
            session['data'],
            [
                OwnershipPayload(**x) if x['type'] == AuthRequestOption.Kind.OWNERSHIP else AddressPayload(**x)
                for x in payload
            ]
        )

    @classmethod
    def unpack_session_data(cls, b64data: str, static_secret: bytes) -> dict:
        bytes_data = base64.b64decode(b64data)
        nonce_length = 24

        nonce = bytes_data[:nonce_length]
        bytes_payload = bytes_data[nonce_length:]

        box = nacl.secret.SecretBox(static_secret)

        try:
            decrypted = box.decrypt(bytes_payload, nonce)
        except Exception:
            raise SessionUnpackException

        payload = json.loads(decrypted.decode())
        if not payload.get('tonconnect'):
            raise InvalidSessionPayloadException

        ts = int(time.time())
        if payload['tonconnect']['exp'] < ts:
            raise SessionExpiredException

        return {
            'sk': base64.b64decode(payload['tonconnect']['sk']),
            'data': payload['data']
        }

    @staticmethod
    def verify_ton_ownership(payload: OwnershipPayload, client_id: str) -> bool:
        msg = f'tonlogin/ownership/{payload.wallet_version}/{payload.address}/{client_id}'

        pubkey = base64.b64decode(payload.pubkey)
        signature = base64.b64decode(payload.signature)

        key = nacl.signing.VerifyKey(pubkey)

        try:
            key.verify(msg.encode(), signature)
        except Exception:
            return False

        bytes_address = base64.urlsafe_b64decode(payload.address)
        workchain_id = int.from_bytes(bytes_address[1:2], byteorder='big')

        options = {
            'workchain_id': workchain_id,
            'public_key': base64.urlsafe_b64decode(payload.pubkey),
        }
        wallet = wallet_manager.create_wallet(payload.wallet_version, options)
        user_friendly_address = wallet.get_user_friendly_address()

        return user_friendly_address == payload.address

#


class TonConnectException(Exception):
    ...


class SessionUnpackException(TonConnectException):
    ...


class InvalidSessionPayloadException(TonConnectException):
    ...


class InvalidPayloadException(TonConnectException):
    ...


class SessionExpiredException(TonConnectException):
    ...
