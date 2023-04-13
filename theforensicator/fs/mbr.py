"""Parser for MBR"""

from .defs import *
from struct import unpack_from, unpack

import theforensicator

class MBR(object):
    """MBR Partition Table parser"""

    MSDOS_MBR_SIGNATURE = 0xaa55
    EFI_PMBR_OSTYPE_EFI = 0xEF
    EFI_PMBR_OSTYPE_EFI_GPT = 0xEE

    def __init__(self, ewf_image: "theforensicator.app.EWFImage"):
        """Initialize the MBR object

        Args:
            ewf_image: The EWFImage object used as a base
        """
        self.handle = ewf_image.handle
        self.verbose = ewf_image.verbose
        self.mbr = {
            "partition_records" : []
        }

        self._read_mbr()

        # not very useful
        if self.verbose:
            pass
            #self._print_mbr_info()

    def _read_mbr(self):
        """Reads the MBR partition table"""
        self.mbr_header = self.read_mbr_header()
        self.mbr_partitions = self.mbr["partition_records"]

    def read_mbr_header(self):
        offset = self.handle.get_offset()
        mbr_header = self.handle.read(512)

        # https://elixir.bootlin.com/linux/latest/source/block/partitions/efi.h

        self.mbr["signature"] = unpack_from("<H", mbr_header, offset=510)[0]

        if self.mbr["signature"] != MBR.MSDOS_MBR_SIGNATURE:
            print("[!] Failed to read MBR header, wrong signature %#x found." % self.mbr["signature"])
            exit(-1)

        self.mbr["boot_code"] = unpack_from("<440s", mbr_header, offset=0)[0]
        self.mbr["unique_mbr_signature"] = unpack_from("<I", mbr_header, offset=440)[0]
        self.mbr["unknown"] = unpack_from("<H", mbr_header, offset=444)[0]

        for pt_record_nb in range(4):
            partition_record = {}

            partition_record["boot_indicator"] = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16))[0]
            partition_record["start_head"]  = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16) + 1)[0]
            partition_record["start_sector"]  = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16) + 2)[0]
            partition_record["start_track"]  = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16) + 3)[0]
            partition_record["os_type"]  = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16) + 4)[0]
            partition_record["end_head"]  = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16) + 5)[0]
            partition_record["end_sector"]  = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16) + 6)[0]
            partition_record["end_track"]  = unpack_from("<B", mbr_header, offset=446 + (pt_record_nb * 16) + 7)[0]
            partition_record["starting_lba"]  = unpack_from("<I", mbr_header, offset=446 + (pt_record_nb * 16) + 8)[0]
            partition_record["size_in_lba"]  = unpack_from("<I", mbr_header, offset=446 + (pt_record_nb * 16) + 12)[0]

            self.mbr["partition_records"].append(partition_record)
        
        self.handle.seek(offset)

    def _print_mbr_info(self):
        """Prints the informations from the MBR partition table"""
        print("=" * 0x40)
        print("MBR INFOS")

        for (i, partition) in enumerate(self.mbr_partitions):
            print("=" * 0x40)
            print("Partition record %d" % i)
            print("=" * 0x40)

            for key in partition.keys():
                print("\t%-16s : 0x%X" % (key, partition[key]))

        print("=" * 0x40)
