"""Parser for MBR"""

import pyreadpartitions as pypart

import theforensicator


class MBR(object):
    """MBR Partition Table parser"""

    def __init__(self, ewf_image: "theforensicator.app.EWFImage"):
        """Initialize the MBR object

        Args:
            ewf_image: The EWFImage object used as a base
        """
        self.handle = ewf_image.handle
        self.verbosity = ewf_image.verbosity
        self._read_mbr()

        if self.verbosity:
            self._print_mbr_info()

    def _read_mbr(self):
        """Reads the MBR partition table"""
        self.mbr_header = pypart.read_mbr_header(self.handle)
        self.mbr_partitions = pypart.read_mbr_partitions(self.handle, self.mbr_header)

    def _print_mbr_info(self):
        """Prints the informations from the MBR partition table"""
        print("MBR INFOS")
        for partition in self.mbr_partitions:
            for key in partition._asdict().keys():
                print("\t%-16s : %s" % (key, partition._asdict()[key]))
