from abc import ABC
from dataclasses import dataclass
from typing import TypeVar, Generic

from tvm_valuetypes import Cell, deserialize_boc

from .base import Wallet, WalletOptions


@dataclass
class WalletOptionsV3(WalletOptions):
    wallet_id: int = None

    def __post_init__(self) -> None:
        if not self.wallet_id:
            self.wallet_id = 698983191 + self.workchain_id


T = TypeVar('T', bound=WalletOptionsV3)


class WalletV3(Wallet[T], Generic[T], ABC):
    def __init__(self, options: T) -> None:
        super().__init__(options)

    def _create_data_cell(self) -> Cell:
        cell = Cell()

        cell.data.put_arbitrary_uint(0, 32)
        cell.data.put_arbitrary_uint(self._options.wallet_id, 32)
        cell.data.put_arbitrary_uint(int.from_bytes(self._options.public_key, byteorder='big'), 256)

        return cell


#


@dataclass
class WalletOptionsV3R1(WalletOptionsV3):
    ...


class WalletV3R1(WalletV3[WalletOptionsV3R1]):
    @staticmethod
    def get_name() -> str:
        return 'V3R1'

    def _create_code_cell(self) -> Cell:
        return deserialize_boc(bytes.fromhex('B5EE9C724101010100620000C0FF0020DD2082014C97BA9730ED44D0D70B1FE0A4F2608308D71820D31FD31FD31FF82313BBF263ED44D0D31FD31FD3FFD15132BAF2A15144BAF2A204F901541055F910F2A3F8009320D74A96D307D402FB00E8D101A4C8CB1FCB1FCBFFC9ED543FBE6EE0'))  # noqa

#


@dataclass
class WalletOptionsV3R2(WalletOptionsV3):
    ...


class WalletV3R2(WalletV3[WalletOptionsV3R2]):
    @staticmethod
    def get_name() -> str:
        return 'V3R2'

    def _create_code_cell(self) -> Cell:
        return deserialize_boc(bytes.fromhex('B5EE9C724101010100710000DEFF0020DD2082014C97BA218201339CBAB19F71B0ED44D0D31FD31F31D70BFFE304E0A4F2608308D71820D31FD31FD31FF82313BBF263ED44D0D31FD31FD3FFD15132BAF2A15144BAF2A204F901541055F910F2A3F8009320D74A96D307D402FB00E8D101A4C8CB1FCB1FCBFFC9ED5410BD6DAD'))  # noqa
