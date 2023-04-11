"""Main module."""

from struct import unpack

# import pyewf as test
import yaml

from .fs import GPT, MBR, NTFS

MBR_MAGIC = 0xD08EC033
MBR_SIZE = 512

NTFS_MAGIC = 0x4E9052EB

SECTOR_SIZE = 512

UINT32 = 4
UINT64 = 8


class EWFImage(object):
    """Object that reads the content of the EWF file and parses the content"""

    def __init__(self, filename: str) -> None:
        """Initialize the object with default values and the given filename

        Args:
            filename: The filename of the file to parse
        """
        self.filename = filename
        self.handle = None
        self.verbosity = True
        self.ntfs_partitions = []
        self.mft_dump_location = None
        self.out_file_location = None

    def __enter__(self) -> None:
        """Open a handle on EWF files and read the content. Called when we enter
        a `with` block
        """

        try:
            import pyewf

            self.handle = pyewf.handle()
            self.handle.open(pyewf.glob(self.filename))
        except ModuleNotFoundError:
            print("[!]\tCould not load pyewf, using python implementation...")
            from .ewf import Ewf

            self.handle = Ewf(self.filename)

        return self

    def _read_int(self, offset: int) -> int:
        """Reads an Integer at the given offset

        Args:
            offset: Where we want to read

        Returns:
            The value that has been read (as a int)

        Raises:
            ValueError: If offset is out of bounds
        """
        curr_off = self.handle.get_offset()
        buf = self.handle.read_buffer_at_offset(UINT32, offset)
        self.handle.seek(curr_off)
        return unpack("<I", buf)[0]

    def _read_bytes(self, offset: int, nb_bytes: int) -> bytes:
        """Reads some bytes at the given offset

        Args:
            offset: Where we want to read

        Returns:
            The bytes that has been read

        Raises:
            ValueError: If offset is out of bounds
        """
        curr_off = self.handle.get_offset()
        buf = self.handle.read_buffer_at_offset(nb_bytes, offset)
        self.handle.seek(curr_off)
        return buf

    def _is_mbr_partition(self) -> bool:
        """Check if the beginning of the disk matches a MBR magic number

        Returns:
            True if it is a MBR partition table

        Raises:
            ValueError: If the disk size is 0
        """
        return self._read_int(0) == MBR_MAGIC

    def _get_partitions(self):
        """Parses the partition table"""
        self.mbr = MBR(self)
        self.mbr_partitions = self.mbr.mbr_partitions

        self.gpt = GPT(self)
        self.gpt_partitions = self.gpt.gpt_partitions

    def _read_sector(self, nb_sector: int) -> bytes:
        """Read the given sector

        Args:
            nb_sector: Index of the sector to read

        Returns:
            The content of the sector

        Raises:
            ValueError: If we try to read out of bounds
        """
        return self._read_bytes(nb_sector * 512, SECTOR_SIZE)

    def _read_int_at_sector_offset(self, nb_sector: int, offset: int):
        """Read an int at a given offset in the given sector

        Args:
            nb_sector: Index of the sector to read
            offset: The offset where we want to read within the sector

        Returns:
            The int we wanted to read

        Raises:
            ValueError: If we try to read out of bounds
        """
        return self._read_int((nb_sector * 512) + offset)

    def _find_ntfs_partitions(self):
        """Retrieve all the NTFS partitions (_get_partitions needs to be called
        before this function)
        """
        for partition in self.gpt_partitions:
            magic = self._read_int_at_sector_offset(partition.first_lba, 0)
            if magic == NTFS_MAGIC:
                self.ntfs_partitions.append(NTFS(self, partition))

    def read_ewf(self):
        """Read the EWF file, and parse the partition tables"""
        # self.handle.display_properties()

        if not self._is_mbr_partition():
            print("[!] No MBR partition found, exiting...")
            exit(-1)

        print("[+] MBR partition found.")

        self._get_partitions()

        self._find_ntfs_partitions()

    def analyze_ntfs(self, out_dir: str, dump_dir: str, resolve_mft_file: str):
        """Analyze the NTFS partitions to extract the wanted files

        Args:
            out_dir: Directory where non-resolved MFT will be stored
            dump_dir: Directory where non-resolved MFT is stored
            resolve_mft_file: Output file of resolved MFT in JSON format
        """
        out_file = ""
        dump_file = ""

        if out_dir:
            out_file = f"{out_dir}/mft_dump.json"

        if dump_dir:
            dump_file = f"{dump_dir}/mft_dump.json"

        for partition in self.ntfs_partitions:
            partition.analyze_ntfs_header(out_file, dump_file, resolve_mft_file)
            partition.dump_file(["C:\\Windows\\System32\\config\\SYSTEM"])

    def __exit__(self, exception_type, exception_value, exception_traceback):
        """Close and clean everything. Called when we exit a `with` block."""
        pass
