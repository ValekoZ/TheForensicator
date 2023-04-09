"""Main module."""

from struct import unpack

from .fs import GPT, MBR, NTFS
from .pyewf import Ewf

MBR_MAGIC = 0xD08EC033
MBR_SIZE = 512

NTFS_MAGIC = 0x4E9052EB

SECTOR_SIZE = 512

UINT32 = 4
UINT64 = 8

class EWFImage(object):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.handle             = None
        self.verbosity          = True
        self.ntfs_partitions    = []
        self.mft_dump_location  = None
        self.out_file_location  = None

    """Open a handle on EWF files and read the content.
    """

    def __enter__(self) -> None:
        self.handle = Ewf(self.filename)
        return self

    def _read_int(self, offset: int) -> int:
        curr_off = self.handle.get_offset()
        buf = self.handle.read_buffer_at_offset(UINT32, offset)
        self.handle.seek(curr_off)
        return unpack("<I", buf)[0]

    def _read_bytes(self, offset: int, nb_bytes: int) -> bytes:
        curr_off = self.handle.get_offset()
        buf = self.handle.read_buffer_at_offset(nb_bytes, offset)
        self.handle.seek(curr_off)
        return buf

    def _is_mbr_partition(self) -> bool:
        return self._read_int(0) == MBR_MAGIC

    def _get_partitions(self):
        self.mbr = MBR(self)
        self.mbr_partitions = self.mbr.mbr_partitions

        self.gpt = GPT(self)
        self.gpt_partitions = self.gpt.gpt_partitions

    def _read_sector(self, nb_sector: int) -> bytes:
        return self._read_bytes(nb_sector * 512, SECTOR_SIZE)

    def _read_int_at_sector_offset(self, nb_sector: int, offset: int):
        return self._read_int((nb_sector * 512) + offset)

    def _find_ntfs_partitions(self):
        for partition in self.gpt_partitions:
            magic = self._read_int_at_sector_offset(partition.first_lba, 0)
            if magic == NTFS_MAGIC:
                self.ntfs_partitions.append(NTFS(self, partition))

    def read_ewf(self) -> bytes:
        self.handle.display_properties()

        if not self._is_mbr_partition():
            print("[!] No MBR partition found, exiting...")
            exit(-1)

        print("[+] MBR partition found.")

        self._get_partitions()

        self._find_ntfs_partitions()

    """
    """
    def analyze_ntfs(self, out_dir: str, dump_dir: str):
        out_file    = ""
        dump_file   = ""

        if out_dir:
            out_file        = f'{out_dir}/mft_dump.json'
        
        if dump_dir:
            dump_file       = f'{dump_dir}/mft_dump.json'

        for partition in self.ntfs_partitions:
            partition.analyze_ntfs_header(out_file, dump_file)

    def __exit__(self, exception_type, exception_value, exception_traceback):
        pass
