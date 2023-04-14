"""Parser for GPT"""

from struct import unpack_from, unpack
from .defs import *
import theforensicator


class GPT(object):
    """MBR Partition Table parser"""

    GPT_HEADER_SIGNATURE = 0x5452415020494645

    def __init__(self, ewf_image: "theforensicator.app.EWFImage") -> None:
        """Initialize the MBR object

        Args:
            ewf_image: The EWFImage object used as a base
        """
        self.handle = ewf_image.handle
        self.verbose = ewf_image.verbose
        self.gpt = {}

        self._read_gpt()

        if self.verbose:
            self._print_gpt_info()

    def _read_gpt(self):
        """Reads the GPT partition table"""
        self.gpt_header = self.read_gpt_header()
        self.gpt_partitions = self.read_gpt_partitions(lba_size=512)

    def read_gpt_header(self) -> bytes:
        offset = self.handle.get_offset()
        self.handle.seek(512)

        gpt_header = self.handle.read(512)

        self.gpt["signature"] = unpack_from("<Q", gpt_header, offset=0)[0]

        if self.gpt["signature"] != GPT.GPT_HEADER_SIGNATURE:
            print("[!] Failed to read GPT header, wrong signature %#x found." % self.mbr["signature"])
            exit(-1)

        self.gpt["revision"] = unpack_from("<I", gpt_header, offset=8)[0]
        self.gpt["header_size"] = unpack_from("<I", gpt_header, offset=12)[0]
        self.gpt["header_crc32"] = unpack_from("<I", gpt_header, offset=16)[0]
        self.gpt["reserved1"] = unpack_from("<I", gpt_header, offset=20)[0]
        self.gpt["my_lba"] = unpack_from("<Q", gpt_header, offset=24)[0]
        self.gpt["alternate_lba"] = unpack_from("<Q", gpt_header, offset=32)[0]
        self.gpt["first_usable_lba"] = unpack_from("<Q", gpt_header, offset=40)[0]
        self.gpt["last_usable_lba"] = unpack_from("<Q", gpt_header, offset=48)[0]
        self.gpt["disk_guid"] = "%08X-%04X-%04X-%04X-%s" % (
            unpack_from("<I", gpt_header, offset=56)[0],
            unpack_from("<H", gpt_header, offset=60)[0],
            unpack_from("<H", gpt_header, offset=62)[0],
            unpack_from("<H", gpt_header, offset=64)[0],
            unpack_from("<8s", gpt_header, offset=66)[0].hex().upper()
        )
        self.gpt["partition_entry_lba"] = unpack_from("<Q", gpt_header, offset=72)[0]
        self.gpt["num_partition_entries"] = unpack_from("<I", gpt_header, offset=80)[0]
        self.gpt["sizeof_partition_entry"] = unpack_from("<I", gpt_header, offset=84)[0]
        self.gpt["partition_entry_array_crc32"] = unpack_from("<I", gpt_header, offset=88)[0]

        self.handle.seek(offset)
        return gpt_header

    def read_gpt_partitions(self, lba_size=512):
        offset = self.handle.get_offset()

        partition_entry_lba = self.gpt["partition_entry_lba"]
        self.handle.seek(partition_entry_lba * lba_size)

        gpt_partitions = []

        for entry_idx in range(self.gpt["num_partition_entries"]):
            entry = self.handle.read(self.gpt["sizeof_partition_entry"])

            partition_entry = {}
            partition_entry["partition_type_guid"] = "%08X-%04X-%04X-%04X-%s" % (
                unpack_from("<I", entry, offset=0)[0],
                unpack_from("<H", entry, offset=4)[0],
                unpack_from("<H", entry, offset=6)[0],
                unpack_from(">H", entry, offset=8)[0],
                unpack_from("<6s", entry, offset=10)[0].hex().upper()
            )
            partition_entry["unique_partition_guid"] = "%08X-%04X-%04X-%04X-%s" % (
                unpack_from("<I", entry, offset=16)[0],
                unpack_from("<H", entry, offset=20)[0],
                unpack_from("<H", entry, offset=22)[0],
                unpack_from(">H", entry, offset=24)[0],
                unpack_from("<6s", entry, offset=26)[0].hex().upper()
            )
            partition_entry["first_lba"] = unpack_from("<Q", entry, offset=32)[0]
            partition_entry["last_lba"] = unpack_from("<Q", entry, offset=40)[0]

            # Determine last entry
            if not partition_entry["first_lba"] and not partition_entry["last_lba"]:
                break

            gpt_partitions.append(partition_entry)

        self.handle.seek(offset)
        return gpt_partitions

    def _print_gpt_info(self):
        """Prints the informations from the GPT partition table"""
        print("GPT INFOS")
        print("=" * 89)
        print("  Index  Type" + ' '*30 + "    Offset Start (Sectors)    Length (Sectors)")
        print("-------  ----" + '-'*30 + "  ------------------------  ------------------")

        for (i, partition) in enumerate(self.gpt_partitions):
            print(("%7d  %-34s" + "  %24d  %18d") % (
                i, 
                PARTITION_TYPE_GUID[partition["partition_type_guid"]],
                partition["first_lba"],
                (partition["last_lba"] - partition["first_lba"] + 1)
            ))
        
        print("=" * 89)