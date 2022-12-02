import base64

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, TypeVar

from tvm_valuetypes import Cell


@dataclass
class WalletOptions:
    workchain_id: int
    public_key: bytes


T = TypeVar('T', bound=WalletOptions)


class Wallet(Generic[T], ABC):
    def __init__(self, options: T) -> None:
        self._options = options

    @staticmethod
    @abstractmethod
    def get_name() -> str:
        raise NotImplementedError

    @abstractmethod
    def _create_code_cell(self) -> Cell:
        raise NotImplementedError

    @abstractmethod
    def _create_data_cell(self) -> Cell:
        raise NotImplementedError

    @staticmethod
    def _create_state_init(code: Cell = None, data: Cell = None) -> Cell:
        cell = Cell()

        code_bits = 1 if code is not None else 0
        data_bits = 1 if data is not None else 0

        cell.data.put_arbitrary_uint(0, 1)              # maybe depth
        cell.data.put_arbitrary_uint(0, 1)              # maybe tiktok
        cell.data.put_arbitrary_uint(code_bits, 1)      # maybe code
        cell.data.put_arbitrary_uint(data_bits, 1)      # maybe data
        cell.data.put_arbitrary_uint(0, 1)              # maybe library

        if code:
            cell.refs.append(code)

        if data:
            cell.refs.append(data)

        return cell

    def get_raw_address(self) -> str:
        code = self._create_code_cell()
        data = self._create_data_cell()

        state_init = self._create_state_init(code, data)
        state_init_hash = state_init.hash()

        return f'{self._options.workchain_id}:{state_init_hash.hex()}'

    @staticmethod
    def _calc_crc16(data: bytes) -> bytes:  # source: toncenter/tonweb/src/utils/Utils.js
        assert len(data) == 34

        data += b'\0' * 2

        poly = 0x1021
        reg = 0

        for byte in data:
            mask = 0x80
            while mask > 0:
                reg <<= 1

                if byte & mask:
                    reg += 1

                mask >>= 1

                if reg > 0xffff:
                    reg &= 0xffff
                    reg ^= poly

        addr_bits_cnt = 256
        a, b = reg // addr_bits_cnt, reg % addr_bits_cnt
        a, b = map(lambda x: x.to_bytes(1, byteorder='big'), (a, b))
        return a + b

    def get_user_friendly_address(self) -> str:
        raw_address = self.get_raw_address()
        workchain_id, address = raw_address.split(':')

        tag = 0x11.to_bytes(1, byteorder='big')  # always bounceable
        workchain_id = int(workchain_id).to_bytes(1, byteorder='big', signed=True)
        address = bytes.fromhex(address)

        addr = tag + workchain_id + address
        crc16 = self._calc_crc16(addr)

        return base64.urlsafe_b64encode(addr + crc16).decode()
