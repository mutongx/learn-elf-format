import sys
import mmap
from contextlib import ExitStack
from typing import Union


class MmapSlice:
    def __init__(self, mmap: mmap.mmap, offset: int, size: int) -> None:
        self._mmap = mmap
        self._offset = offset
        self._size = size

    def __getitem__(self, index: Union[slice, int]):
        if isinstance(index, slice):
            start = index.start if index.start is not None else 0
            stop = index.stop if index.stop is not None else self._size
            return self._mmap[self._offset + start : self._offset + stop : index.step]
        return self._mmap[self._offset + index]

    def slice(self, offset: int, size: int):
        if self._offset + offset + size > self._offset + self._size:
            raise ValueError("required slice exceeds actual size")
        return MmapSlice(self._mmap, self._offset + offset, size)


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


def main(file_path: str):
    with ELFFile(file_path) as f:
        pass


if __name__ == "__main__":
    file_path = sys.argv[1]
    main(file_path)
