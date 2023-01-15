import sys
import mmap
from contextlib import ExitStack
from typing import Union, List, Dict, Tuple, overload


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
    FIELD_MAPPING: List[Tuple[str, int]] = []

    def __init__(self, data: MmapSlice) -> None:
        self._data = data
        self._fields: Dict[str, Tuple[int, int]] = {}
        offset = 0
        for name, size in self.FIELD_MAPPING:
            if name in self._fields:
                raise RuntimeError(f"duplicate field name: {name}")
            self._fields[name] = (offset, size)
            offset += size
        if offset != data.size:
            raise ValueError(
                f"size of data ({data.size}) does not match with FIELD_MAPPING definition"
            )

    def __getattr__(self, key: str) -> Union[bytes, int]:
        offset, size = self._fields[key]
        return self._data[offset : offset + size]


class ELFIdentification(StructReader):
    FIELD_MAPPING = [
        ("magic", 4),
        ("word_size", 1),
        ("endianness", 1),
        ("ident_version", 1),
        ("os_abi", 1),
        ("os_abi_version", 1),
        ("padding", 7),
    ]


class ELF64Header(StructReader):
    FIELD_MAPPING = ELFIdentification.FIELD_MAPPING + [
        ("object_type", 2),
        ("architecture", 2),
        ("version", 4),
        ("entry_address", 8),
        ("program_header_offset", 8),
        ("section_header_offset", 8),
        ("flags", 4),
        ("elf_header_size", 2),
        ("program_header_size", 2),
        ("program_header_count", 2),
        ("section_header_size", 2),
        ("section_header_count", 2),
        ("section_header_index", 2),
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
        if ident.word_size != b"\x02":
            raise RuntimeError("only 64-bit ELF file is supported")
        if ident.endianness != b"\x01":
            raise RuntimeError("only little-endian ELF file is supported")
        if ident.ident_version != b"\x01":
            raise RuntimeError("invalid ELF identification version")


if __name__ == "__main__":
    file_path = sys.argv[1]
    main(file_path)
