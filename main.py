import struct
import sys
import mmap
from contextlib import ExitStack
from typing import Union, Optional, List, Dict, Tuple, overload


class MmapSlice:
    def __init__(self, mmap: mmap.mmap, offset: int, size: int) -> None:
        self._mmap = mmap
        self._offset = offset
        self._size = size

    @overload
    def __getitem__(self, __i: int) -> int:
        ...

    @overload
    def __getitem__(self, __s: slice) -> bytes:
        ...

    def __getitem__(self, index: Union[int, slice]):
        if isinstance(index, slice):
            start = index.start if index.start is not None else 0
            stop = index.stop if index.stop is not None else self._size
            return self._mmap[self._offset + start : self._offset + stop : index.step]
        return self._mmap[self._offset + index]

    def slice(self, offset: int, size: int):
        if self._offset + offset + size > self._offset + self._size:
            raise ValueError("required slice exceeds actual size")
        return MmapSlice(self._mmap, self._offset + offset, size)

    @property
    def size(self):
        return self._size


class StructReader:
    FIELD_MAPPING: List[Tuple[str, int, Optional[str]]] = []

    def __init__(self, data: MmapSlice) -> None:
        self._data = data
        self._fields: Dict[str, Tuple[int, int, Optional[str]]] = {}
        offset = 0
        for name, size, format in self.FIELD_MAPPING:
            if name in self._fields:
                raise RuntimeError(f"duplicate field name: {name}")
            self._fields[name] = (offset, size, format)
            offset += size
        if offset != data.size:
            raise ValueError(
                f"size of data ({data.size}) does not match with FIELD_MAPPING definition"
            )

    def __getattr__(self, key: str) -> Union[bytes, int]:
        offset, size, format = self._fields[key]
        if format is None:
            return self._data[offset : offset + size]
        return struct.unpack(format, self._data[offset : offset + size])[0]


class ELFIdentification(StructReader):
    FIELD_MAPPING = [
        ("magic", 4, None),
        ("elf_class", 1, "<b"),
        ("data_encoding", 1, "<b"),
        ("header_version", 1, "<b"),
        ("os_abi", 1, "<b"),
        ("os_abi_version", 1, "<b"),
        ("padding", 7, None),
    ]


class ELF64Header(StructReader):
    FIELD_MAPPING = ELFIdentification.FIELD_MAPPING + [
        ("object_type", 2, "<h"),
        ("architecture", 2, "<h"),
        ("object_version", 4, "<l"),
        ("entry_address", 8, "<q"),
        ("program_header_offset", 8, "<q"),
        ("section_header_offset", 8, "<q"),
        ("flags", 4, None),
        ("elf_header_size", 2, "<h"),
        ("program_header_size", 2, "<h"),
        ("program_header_count", 2, "<h"),
        ("section_header_size", 2, "<h"),
        ("section_header_count", 2, "<h"),
        ("section_header_index", 2, "<h"),
    ]


class ELFFile:
    def __init__(self, file_path: str):
        self._file_path = file_path

    def __enter__(self):
        self._stack = ExitStack()
        self._file = self._stack.enter_context(open(self._file_path, "rb"))
        self._mmap = mmap.mmap(self._file.fileno(), 0, prot=mmap.PROT_READ)
        return self

    def __exit__(self, *_):
        self._stack.close()

    @property
    def identification(self):
        return ELFIdentification(MmapSlice(self._mmap, 0, 16))

    @property
    def header(self):
        return ELF64Header(MmapSlice(self._mmap, 0, 64))


def main(file_path: str):
    with ELFFile(file_path) as f:
        ident = f.identification
        if ident.magic != b"\x7fELF":
            raise RuntimeError("invalid ELF magic")
        if ident.elf_class != 2:
            raise RuntimeError("only 64-bit ELF file is supported")
        if ident.data_encoding != 1:
            raise RuntimeError("only little-endian ELF file is supported")
        if ident.header_version != 1:
            raise RuntimeError("invalid ELF identification version")


if __name__ == "__main__":
    file_path = sys.argv[1]
    main(file_path)
