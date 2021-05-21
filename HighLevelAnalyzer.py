# High Level Analyzer
# For more information and documentation, please go to
# https://support.saleae.com/extensions/high-level-analyzer-extensions

from enum import IntEnum
from struct import unpack
import struct
from typing import Any, Dict, Set, Union

from saleae.analyzers import (
    HighLevelAnalyzer,
    AnalyzerFrame,
    StringSetting,
    NumberSetting,
    ChoicesSetting,
)
from saleae.data import GraphTime


HEADER_MESSAGE_TYPE_MASK = 0xC0
HEADER_LENGTH_MASK = 0x38
HEADER_CMD_OR_MODE_MASK = 0x07


class MessageType(IntEnum):
    SYS = 0x00
    CMD = 0x40
    INFO = 0x80
    DATA = 0xC0


class Length(IntEnum):
    L1 = 0x00
    L2 = 0x08
    L4 = 0x10
    L8 = 0x18
    L16 = 0x20
    L32 = 0x28


class System(IntEnum):
    SYNC = 0x00
    NACK = 0x02
    ACK = 0x04


class Command(IntEnum):
    TYPE = 0x00
    MODES = 0x01
    SPEED = 0x02
    SELECT = 0x03
    WRITE = 0x04
    EXT_MODE = 0x06
    VERSION = 0x07


class InfoType(IntEnum):
    NAME = 0x00
    RAW = 0x01
    PCT = 0x02
    SI = 0x03
    SYMBOL = 0x04
    MAPPING = 0x05
    MODE_COMBO = 0x06
    UNK7 = 0x07
    UNK8 = 0x08
    UNK9 = 0x09
    UNK10 = 0x0A
    UNK11 = 0x0B
    UNK12 = 0x0C
    MODE_PLUS_8 = 0x20
    FORMAT = 0x80


class Mode(IntEnum):
    M0 = 0x00
    M1 = 0x01
    M2 = 0x02
    M3 = 0x03
    M4 = 0x04
    M5 = 0x05
    M6 = 0x06
    M7 = 0x07


class ExtMode(IntEnum):
    M8 = 0x00
    M9 = 0x01
    M10 = 0x02
    M11 = 0x03
    M12 = 0x04
    M13 = 0x05
    M14 = 0x06
    M15 = 0x07


class DataFormat(IntEnum):
    DATA8 = 0x00
    DATA16 = 0x01
    DATA32 = 0x02
    DATAF = 0x03


def to_name(*name: Union[str, IntEnum]) -> str:
    """Combines names with underscores."""
    return "_".join(n.name if isinstance(n, IntEnum) else n for n in name)


def bit_set(value: int) -> Set[int]:
    """Returns a list containing the index of each bit that is set."""

    def set_bits(n):
        i = 0
        while n:
            if n & 1:
                # return the index of the bit only if it is set
                yield i
            i += 1
            n >>= 1

    return {n for n in set_bits(value)}


def version(num: int) -> str:
    """Format version."""
    major = num >> 28
    minor = (num >> 24) & 0xF
    patch = (num >> 16) & 0xFF
    build = num & 0xFFFF
    return f"{major}.{minor}.{patch:02X}.{build:04X}"


class Message:
    def __init__(self, header: int, start_time: GraphTime):
        self._raw = bytearray([header])
        self.type = MessageType(header & HEADER_MESSAGE_TYPE_MASK)
        self.length = Length(header & HEADER_LENGTH_MASK)

        if self.type == MessageType.SYS:
            self.sys = System(header & HEADER_CMD_OR_MODE_MASK)
        elif self.type == MessageType.CMD:
            self.cmd = Command(header & HEADER_CMD_OR_MODE_MASK)
        else:
            self.mode = Mode(header & HEADER_CMD_OR_MODE_MASK)

        self.start_time = start_time

        # SYS messages don't have a payload (single byte)
        self.complete = self.type == MessageType.SYS

    @property
    def payload_size(self) -> int:
        """Gets size of payload in bytes (decodes ``length``)."""
        return 1 << (self.length >> 3)

    @property
    def total_size(self) -> int:
        """Get total size in bytes."""
        if self.type == MessageType.SYS:
            return 1

        # two extra bytes for header and checksum
        size = self.payload_size + 2

        # INFO message have an extra byte for info type
        if self.type == MessageType.INFO:
            size += 1

        return size

    def append(self, bytecode: int):
        self._raw.append(bytecode)

        if self.type == MessageType.INFO and len(self._raw) == 2:
            self.info_type = InfoType(bytecode & ~InfoType.MODE_PLUS_8)

            if bytecode & InfoType.MODE_PLUS_8:
                self.mode = ExtMode(self.mode)

        if len(self._raw) == self.total_size:
            self.complete = True

    @property
    def data(self) -> Dict[str, Any]:
        """Gets a copy of this object as a dictionary for passing to the analyser."""
        data = self.__dict__.copy()

        # Logic complains that GraphTime type is unsupported
        del data["start_time"]

        # remove duplicate/private data
        data.pop("type")
        data.pop("complete")

        # convert enum values to strings
        for k, v in data.items():
            if isinstance(v, IntEnum):
                data[k] = v.name

        if self.type == MessageType.CMD:
            if self.cmd == Command.TYPE:
                data["type_id"] = hex(self._raw[1])
            elif self.cmd == Command.MODES:
                data["num_modes"] = self._raw[1] + 1
            elif self.cmd == Command.SPEED:
                data["baud_rate"] = str(int.from_bytes(self._raw[1:5], "little"))
            elif self.cmd == Command.SELECT:
                data["mode"] = str(self._raw[1])
            elif self.cmd == Command.WRITE:
                cmd = self._raw[1]
                if cmd & 0x20:
                    num_combos = cmd & 0xF
                    combos = [
                        {"mode": c >> 4, "dataset": c & 0xF}
                        for c in self._raw[2 : 2 + num_combos]
                    ]
                    data["payload"] = f"combo mode: {combos}".replace("'", "")
                elif cmd == 0x03:
                    data["payload"] = "string:" + self._raw[2:-1].decode().strip("\0")
                else:
                    data["payload"] = f"unknown {self._raw[1:-1].hex(' ')}"
            elif self.cmd == Command.VERSION:
                data["fw_ver"] = version(int.from_bytes(self._raw[1:5], "little"))
                data["hw_ver"] = version(int.from_bytes(self._raw[5:9], "little"))
        elif self.type == MessageType.INFO:
            if self.info_type == InfoType.NAME:
                if self.length == Length.L16 and self._raw[7] == 0:
                    # extra flags included
                    data["name"] = self._raw[2:7].decode().strip("\0")
                    data["flags"] = self._raw[8:14].hex(" ")
                else:
                    data["name"] = self._raw[2:-1].decode().strip("\0")
                # TODO: handle extended mode info
            elif self.info_type == InfoType.RAW:
                data["raw_min"], data["raw_max"] = unpack("<ff", self._raw[2:-1])
            elif self.info_type == InfoType.PCT:
                data["pct_min"], data["pct_max"] = unpack("<ff", self._raw[2:-1])
            elif self.info_type == InfoType.SI:
                data["si_min"], data["si_max"] = unpack("<ff", self._raw[2:-1])
            elif self.info_type == InfoType.SYMBOL:
                data["symbol"] = self._raw[2:-1].decode().strip("\0")
            elif self.info_type == InfoType.MAPPING:
                pass  # TODO
            elif self.info_type == InfoType.MODE_COMBO:
                combos = unpack("<" + "H" * (self.payload_size // 2), self._raw[2:-1])
                data["combos"] = ", ".join(str(bit_set(c)) for c in combos if c != 0)
            elif self.info_type == InfoType.FORMAT:
                data["data_sets"] = str(self._raw[2])
                data["format"] = DataFormat(self._raw[3]).name
                data["figures"] = str(self._raw[4])
                data["decimals"] = str(self._raw[5])
        elif self.type == MessageType.DATA:
            if self.length == Length.L8 and self.mode == Mode.M0:
                # Decode as motor data (could be something else though)
                data["speed"] = str(
                    int.from_bytes(self._raw[1:2], "little", signed=True)
                )
                data["pos"] = str(int.from_bytes(self._raw[2:6], "little", signed=True))
                data["abs pos"] = str(
                    int.from_bytes(self._raw[6:8], "little", signed=True)
                )

            data["data8"] = str(
                struct.unpack_from("<" + "b" * self.payload_size, self._raw, 1)
            )
            data["u8"] = " ".join(
                f"0x{i:02X}"
                for i in struct.unpack_from("<" + "B" * self.payload_size, self._raw, 1)
            )

            if self.payload_size >= 2:
                data["data16"] = str(
                    struct.unpack_from(
                        "<" + "h" * (self.payload_size // 2), self._raw, 1
                    )
                )
                data["u16"] = " ".join(
                    f"0x{i:04X}"
                    for i in struct.unpack_from(
                        "<" + "H" * (self.payload_size // 2), self._raw, 1
                    )
                )

            if self.payload_size >= 4:
                data["data32"] = str(
                    struct.unpack_from(
                        "<" + "i" * (self.payload_size // 4), self._raw, 1
                    )
                )
                data["u32"] = " ".join(
                    f"0x{i:08X}"
                    for i in struct.unpack_from(
                        "<" + "I" * (self.payload_size // 4), self._raw, 1
                    )
                )
                data["dataf"] = str(
                    struct.unpack_from(
                        "<" + "f" * (self.payload_size // 4), self._raw, 1
                    )
                )

        return data


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=("A", "B"))

    COMMAND_HEADER_FORMAT = "CMD: {{data.cmd}}: "
    INFO_HEADER_FORMAT = "INFO: {{data.info_type}} mode={{data.mode}}: "

    # A list of types this analyzer produces, providing a way to
    # customize the way frames are displayed in Logic 2.
    result_types = {
        to_name(MessageType.SYS): {"format": "SYS: {{data.sys}}"},
        to_name(MessageType.CMD, Command.TYPE): {
            "format": COMMAND_HEADER_FORMAT + "id={{data.type_id}}"
        },
        to_name(MessageType.CMD, Command.MODES): {
            "format": COMMAND_HEADER_FORMAT
            + "modes={{data.num_modes}} views={{data.num_views}}"
        },
        to_name(MessageType.CMD, Command.TYPE): {
            "format": COMMAND_HEADER_FORMAT + "id={{data.type_id}}"
        },
        to_name(MessageType.CMD, Command.SPEED): {
            "format": COMMAND_HEADER_FORMAT + "baud_rate={{data.baud_rate}}"
        },
        to_name(MessageType.CMD, Command.WRITE): {
            "format": COMMAND_HEADER_FORMAT + "payload={{data.payload}}"
        },
        to_name(MessageType.CMD, Command.VERSION): {
            "format": COMMAND_HEADER_FORMAT
            + "fw_ver={{data.fw_ver}} hw_ver={{data.hw_ver}}"
        },
        to_name(MessageType.INFO, InfoType.NAME): {
            "format": INFO_HEADER_FORMAT + "name={{data.name}} flags={{data.flags}}"
        },
        to_name(MessageType.INFO, InfoType.RAW): {
            "format": INFO_HEADER_FORMAT + "min={{data.raw_min}} max={{data.raw_max}}"
        },
        to_name(MessageType.INFO, InfoType.PCT): {
            "format": INFO_HEADER_FORMAT + "min={{data.pct_min}} max={{data.pct_max}}"
        },
        to_name(MessageType.INFO, InfoType.SI): {
            "format": INFO_HEADER_FORMAT + "min={{data.si_min}} max={{data.si_max}}"
        },
        to_name(MessageType.INFO, InfoType.SYMBOL): {
            "format": INFO_HEADER_FORMAT + "symbol={{data.symbol}}"
        },
        to_name(MessageType.INFO, InfoType.MAPPING): {
            "format": INFO_HEADER_FORMAT + "<TODO>"
        },
        to_name(MessageType.INFO, InfoType.FORMAT): {
            "format": INFO_HEADER_FORMAT
            + "sets={{data.data_sets}} format={{data.format}} figures={{data.figures}} decimals={{data.decimals}}"
        },
        to_name(MessageType.INFO, InfoType.MODE_COMBO): {
            "format": INFO_HEADER_FORMAT + "combos={{data.combos}}"
        },
        to_name(MessageType.DATA): {"format": "DATA: {{data.mode}} {{data.values}}"},
    }

    def __init__(self):
        """
        Initialize HLA.

        Settings can be accessed using the same name used above.
        """

        print(
            "Settings:",
            self.my_string_setting,
            self.my_number_setting,
            self.my_choices_setting,
        )

        self.message = None

    def decode(self, frame: AnalyzerFrame):
        """
        Process a frame from the input analyzer, and optionally return a single
        `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        """

        bytecode = frame.data["data"][0]

        print("bytecode", hex(bytecode))

        if self.message is None:
            # this is the header
            self.message = Message(bytecode, frame.start_time)
        else:
            self.message.append(bytecode)

        if self.message.complete:
            msg, self.message = self.message, None
            name = to_name(msg.type)

            if msg.type == MessageType.CMD:
                name = to_name(name, msg.cmd)
            elif msg.type == MessageType.INFO:
                name = to_name(name, msg.info_type)

            return AnalyzerFrame(name, msg.start_time, frame.end_time, msg.data)
