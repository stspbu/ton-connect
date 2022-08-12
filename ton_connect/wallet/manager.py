from .V3 import *
from .V4 import *


class WalletManager:
    _version_to_wallet_cls = {
        w.get_name(): (w, o) for w, o in [
            (WalletV3R1, WalletOptionsV3R1),
            (WalletV3R2, WalletOptionsV3R2),
            (WalletV4R1, WalletOptionsV4R1),
            (WalletV4R2, WalletOptionsV4R2),
        ]
    }

    def create_wallet(self, version: str, options: dict) -> Wallet:
        version = version.upper()
        if version not in self._version_to_wallet_cls:
            raise NotImplementedError

        wallet_cls, options_cls = self._version_to_wallet_cls[version]
        return wallet_cls(options_cls(**options))


wallet_manager = WalletManager()
