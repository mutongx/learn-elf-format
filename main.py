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

    def find(self, ch: int, begin: int, end: Optional[int] = None):
        if begin >= self._size:
            return None
        if end is None or end >= self._size:
            end = self._size
        for index in range(begin, end):
            if self._mmap[self._offset + index] == ch:
                return index
        return None

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


class StringTable:
    def __init__(self, data: MmapSlice) -> None:
        self._data = data

    def get(self, offset: int):
        null_index = self._data.find(0x00, offset, None)
        return self._data[offset:null_index].decode()


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


class ELF64ProgramHeader(StructReader):
    FIELD_MAPPING = [
        ("type", 4, "<l"),
        ("flags", 4, "<l"),
        ("offset", 8, "<q"),
        ("virtual_address", 8, "<q"),
        ("physical_address", 8, "<q"),
        ("size_in_file", 8, "<q"),
        ("size_in_memory", 8, "<q"),
        ("alignment", 8, "<q"),
    ]


class ELF64Program:
    def __init__(self, header: ELF64ProgramHeader, data: MmapSlice) -> None:
        self._header = header
        self._data = data

    @property
    def header(self):
        return self._header

    @property
    def data(self):
        return self._data


class ELF64SectionHeader(StructReader):
    FIELD_MAPPING = [
        ("name", 4, "<l"),
        ("type", 4, "<l"),
        ("flags", 8, "<q"),
        ("virtual_address", 8, "<q"),
        ("offset", 8, "<q"),
        ("size", 8, "<q"),
        ("link", 4, None),
        ("info", 4, None),
        ("alignment", 8, "<q"),
        ("entry_size", 8, "<q"),
    ]


class ELF64Section:
    def __init__(self, name: str, header: ELF64SectionHeader, data: MmapSlice) -> None:
        self._name = name
        self._header = header
        self._data = data

    @property
    def name(self):
        return self._name

    @property
    def header(self):
        return self._header

    @property
    def data(self):
        return self._data


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

    def get_program_header(self, index: int):
        header_size = self.header.program_header_size
        header_count = self.header.program_header_count
        header_offset = self.header.program_header_offset
        assert isinstance(header_size, int)
        assert isinstance(header_count, int)
        assert isinstance(header_offset, int)
        if index >= header_count:
            raise ValueError("invalid program index")
        header = MmapSlice(self._mmap, header_offset + index * header_size, header_size)
        return ELF64ProgramHeader(header)

    def get_program(self, index: int):
        program_header = self.get_program_header(index)
        program_offset = program_header.offset
        program_size = program_header.size_in_file
        assert isinstance(program_offset, int)
        assert isinstance(program_size, int)
        program_data = MmapSlice(self._mmap, program_offset, program_size)
        return ELF64Program(program_header, program_data)

    def get_section_header(self, index: int):
        header_size = self.header.section_header_size
        header_count = self.header.section_header_count
        header_offset = self.header.section_header_offset
        assert isinstance(header_size, int)
        assert isinstance(header_count, int)
        assert isinstance(header_offset, int)
        if index >= header_count:
            raise ValueError("invalid section index")
        header = MmapSlice(self._mmap, header_offset + index * header_size, header_size)
        return ELF64SectionHeader(header)

    def get_section(self, index_or_name: Union[int, str]):
        strtab_index = self.header.section_header_index
        assert isinstance(strtab_index, int)
        strtab_header = self.get_section_header(strtab_index)
        strtab_offset = strtab_header.offset
        strtab_size = strtab_header.size
        assert isinstance(strtab_offset, int)
        assert isinstance(strtab_size, int)
        strtab = StringTable(MmapSlice(self._mmap, strtab_offset, strtab_size))

        if isinstance(index_or_name, int):
            section_index = index_or_name
            section_header = self.get_section_header(section_index)
            section_name_offset = section_header.name
            assert isinstance(section_name_offset, int)
            section_name = strtab.get(section_name_offset)
        else:
            section_count = self.header.section_header_count
            assert isinstance(section_count, int)
            for section_index in range(section_count):
                section_header = self.get_section_header(section_index)
                section_name_offset = section_header.name
                assert isinstance(section_name_offset, int)
                section_name = strtab.get(section_name_offset)
                if section_name == index_or_name:
                    break
            else:
                raise ValueError(f"invalid section name")

        section_offset = section_header.offset
        section_size = section_header.size
        assert isinstance(section_offset, int)
        assert isinstance(section_size, int)

        section_data = MmapSlice(self._mmap, section_offset, section_size)
        return ELF64Section(section_name, section_header, section_data)


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
