from collections import namedtuple
import idc
import idaapi

import itertools
import struct
from awesome.iterator import irange as range
from .core import fix_addresses, get_native_size
from . import exceptions


def Bytes(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Byte, range(start, end))


def Words(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Word, range(start, end, 2))


def Dwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Dword, range(start, end, 4))


def Qwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Qword, range(start, end, 8))


def NativeWords(start, end):
    native_size = get_native_size()

    if native_size == 2:
        return Words(start, end)
    elif native_size == 4:
        return Dwords(start, end)
    elif native_size == 8:
        return Qwords(start, end)


def bytes_until(byte=0, start=None, end=None):
    return iter(Bytes(start, end).next, byte)


def words_until(word=0, start=None, end=None):
    return iter(Words(start, end).next, word)


def dwords_until(dword=0, start=None, end=None):
    return iter(Dwords(start, end).next, dword)


def qwords_until(qword=0, start=None, end=None):
    return iter(Qwords(start, end).next, qword)


def native_words_until(native_word=0, start=None, end=None):
    return iter(NativeWords(start, end).next, native_word)


def Chars(start=None, end=None):
    return itertools.imap(chr, Bytes(start, end))


def chars_until(char='\0', start=None, end=None):
    return iter(Chars(start, end).next, char)


def read_ascii_string(ea, max_length=None):
    if max_length is None:
        end = None
    else:
        end = ea + max_length
    return "".join(chars_until(start=ea, end=end))


def dword_to_bytes(dword):
    return struct.pack(">L", dword)


def read_memory(start, end):
    size = end - start
    return idaapi.get_many_bytes(start, size)


def write_memory(start, data, destructive=False):
    if destructive:
        idaapi.put_many_bytes(start, data)

    else:
        idaapi.patch_many_bytes(start, data)


PatchedByte = namedtuple("PatchedByte", "ea fpos original patched")


def get_patched_bytes(start=None, end=None):
    start, end = fix_addresses(start, end)

    patched_bytes = dict()

    def collector(ea, fpos, original, patched):
        patched_bytes[ea] = PatchedByte(ea, fpos, original, patched)
        return 0

    idaapi.visit_patched_bytes(start, end, collector)

    return patched_bytes


def undefine(start, end):
    idc.MakeUnknown(start, end - start, idc.DOUNK_SIMPLE)


def is_string(ea):
    string_type = idc.GetStringType(idaapi.get_item_head(ea))

    if string_type is None:
        return False

    return True


def get_string(ea):
    """Read the string at the given ea.

    This function uses IDA's string APIs and does not implement any special logic.
    """
    # We get the item-head because the `GetStringType` function only works on the head of an item.
    string_type = idc.GetStringType(idaapi.get_item_head(ea))

    if string_type is None:
        raise exceptions.SarkNoString("No string at 0x{:08X}".format(ea))

    string = idc.GetString(ea, strtype=string_type)

    if not string:
        raise exceptions.SarkNoString("No string at 0x{:08X}".format(ea))

    return string


DATA_TYPE = {
    0x00000000L: 'byte',
    0x10000000L: 'word',
    0x20000000L: 'double word',
    0x30000000L: 'quadro word',
    0x40000000L: 'tbyte',
    0x50000000L: 'ASCII ?',
    0x60000000L: 'Struct ?',
    0x70000000L: 'octaword/xmm word (16 bytes/128 bits)',
    0x80000000L: 'float',
    0x90000000L: 'double',
    0xA0000000L: 'packed decimal real',
    0xB0000000L: 'alignment directive',
    0xC0000000L: '3-byte data (only with support from the processor module)',
    0xD0000000L: 'custom data type',
    0xE0000000L: 'ymm word (32 bytes/256 bits)',
}


class Data(object):
    def __init__(self, ea):
        self.ea = ea

    @property
    def dt_type(self):
        return idaapi.get_flags_novalue(self.ea) & idaapi.DT_TYPE

    def __repr__(self):
        return '<Data(ea=0x{:X}, type_={})>'.format(self.ea, DATA_TYPE[self.dt_type])

    @property
    def is_string(self):
        return is_string(self.ea)

    @property
    def is_dword(self):
        return self.dt_type == idaapi.FF_DWRD

    @property
    def is_word(self):
        return self.dt_type == idaapi.FF_WORD

    @property
    def is_byte(self):
        return self.dt_type == idaapi.FF_BYTE

    @property
    def is_qword(self):
        return self.dt_type == idaapi.FF_QWRD

    @property
    def is_tbyte(self):
        return self.dt_type == idaapi.FF_TBYT

    @property
    def is_asci(self):
        return self.dt_type == idaapi.FF_ASCI

    @property
    def is_struct(self):
        return self.dt_type == idaapi.FF_STRU

    @property
    def is_octaword(self):
        return self.dt_type == idaapi.FF_OWRD

    is_xmm = is_octaword

    @property
    def is_float(self):
        return self.dt_type == idaapi.FF_FLOAT

    @property
    def is_double(self):
        return self.dt_type == idaapi.FF_DOUBLE

    @property
    def is_packed_real(self):
        return self.dt_type == idaapi.FF_PACKREAL

    @property
    def is_align(self):
        return self.dt_type == idaapi.FF_ALIGN

    @property
    def is_3byte(self):
        return self.dt_type == idaapi.FF_3BYTE

    @property
    def is_custom(self):
        return self.dt_type == idaapi.FF_CUSTOM

    @property
    def is_ymm(self):
        return self.dt_type == idaapi.FF_YWRD
