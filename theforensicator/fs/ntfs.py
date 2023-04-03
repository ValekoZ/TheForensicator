import pyreadpartitions as pypart
from struct import unpack, unpack_from
import theforensicator

SECTOR_SIZE = 512
SECTOR_NB   = lambda x : x // SECTOR_SIZE

BIOS_PARAMETER_BLOCK_T  = "HBHBHHBHHHII"
NTFS_BOOT_SECTOR_T      = "<3sQ" + BIOS_PARAMETER_BLOCK_T + "IQQQB3sB3sQI426sH"

MFT_HEADER_SIZE = 48
MFT_ENTRY_SIZE  = 1024
MFT_RECORD_T    = f"<IHHQHHHHIIQHHI{MFT_ENTRY_SIZE - MFT_HEADER_SIZE}s"

# Attribute record type
ATTR_RECORD_T               = "IIBBHHH"
ATTR_RECORD_RESIDENT        = ATTR_RECORD_T + "IHBB"
ATTR_RECORD_NON_RESIDENT    = ATTR_RECORD_T + "QQHB5sQQQQ"

# MFT entry flags
FILE_RECORD_SEGMENT_IN_USE  = 0x1                           # In use
MFT_RECORD_IN_USE           = FILE_RECORD_SEGMENT_IN_USE

FILE_NAME_INDEX_PRESENT     = 0x2                           # Has file name (or $I30) index
MFT_RECORD_IS_DIRECTORY     = FILE_NAME_INDEX_PRESENT       # When this flag is set the file entry represents a directory (that contains sub file entries)

MFT_RECORD_IN_EXTEND        = 0x4                           # According to [APPLE06] this is set for all system files present in the $Extend directory

MFT_RECORD_IS_VIEW_INDEX    = 0x8                           # When this flag is set the file entry represents an index
                                                            # According to [APPLE06] this is set for all indices other than $I30

FILE_MFT        = 0	    # Master file table (mft). Data attribute contains the entries and bitmap attribute records which ones are in use (bit==1).
FILE_MFTMirr    = 1	    # Mft mirror: copy of first four mft records in data attribute. If cluster size > 4kiB, copy of first N mft records, with N = cluster_size / mft_record_size.
FILE_LogFile    = 2	    # Journalling log in data attribute.
FILE_Volume     = 3	    # Volume name attribute and volume information attribute (flags and ntfs version). Windows refers to this file as volume DASD (Direct Access Storage Device).
FILE_AttrDef    = 4	    # Array of attribute definitions in data attribute.
FILE_root       = 5	    # Root directory.
FILE_Bitmap     = 6	    # Allocation bitmap of all clusters (lcns) in data attribute.
FILE_Boot       = 7	    # Boot sector (always at cluster 0) in data attribute.
FILE_BadClus    = 8	    # Contains all bad clusters in the non-resident data attribute.
FILE_Secure     = 9,    # Shared security descriptors in data attribute and two indexes into the descriptors. Appeared in Windows 2000. Before that, this file was named $Quota but was unused.
FILE_UpCase     = 10,	# Uppercase equivalents of all 65536 Unicode characters in data attribute.
FILE_Extend     = 11,	# Directory containing other system files (eg. $ObjId, $Quota, $Reparse and $UsnJrnl). This is new to NTFS3.0.
FILE_reserved12 = 12,	# Reserved for future use (records 12-15).
FILE_reserved13 = 13,
FILE_reserved14 = 14,
FILE_reserved15 = 15,
FILE_first_user = 16    # First user file, used as test limit for whether to allow opening a file or not.


class NTFS(object):
    def __init__(self, ewf_image: "theforensicator.app.EWFImage", partition) -> None:
        self.handle = ewf_image.handle
        self.verbosity = ewf_image.verbosity
        self.partition = partition
        self._start = self.partition.first_lba
        self._end   = self.partition.last_lba

        self.handle.seek(self._start * SECTOR_SIZE)
        self.ntfs_header = NTFSHeader(self._read_nsectors(0, SECTOR_NB(SECTOR_SIZE))).ntfs_header
        self.cluster_block_size = self.ntfs_header["bytes_per_sector"] * self.ntfs_header["sectors_per_cluster"]

        if self.verbosity:
            self._pretty_print()

    def _pretty_print(self):
        print("[+] NTFS partition at sector %#x" % (self._start))

        for header_name in self.ntfs_header.keys():
            if type(self.ntfs_header[header_name]) is bytes:
                print("\t%-18s : %s" % (header_name, self.ntfs_header[header_name]))
            else:
                print("\t%-20s : %#x" % (header_name, self.ntfs_header[header_name]))

    def _read(self, offset: int, nb_bytes: int) -> bytes:
        curr_off = self.handle.get_offset()
        self.handle.seek(self._start * SECTOR_SIZE + offset)
        buf = self.handle.read(nb_bytes)
        self.handle.seek(curr_off)
        return buf

    def _read_sector(self, sector_idx: int) -> bytes:
        return self._read(sector_idx * SECTOR_SIZE, SECTOR_SIZE)

    def _read_nsectors(self, sector_idx: int, nb_sector: int) -> bytes:
        return self._read(sector_idx * SECTOR_SIZE, nb_sector * SECTOR_SIZE)

    def _read_cluster(self, cluster_idx: int) -> bytes:
        return self._read(cluster_idx * self.cluster_block_size, self.cluster_block_size)

    def _read_cluster_nbytes(self, cluster_idx: int, nb_bytes: int) -> bytes:
        return self._read(cluster_idx * self.cluster_block_size, nb_bytes)

    def _read_mft_entry(self, mft_entry_idx: int):
        return self._read((self.mft_start * self.cluster_block_size) + (MFT_ENTRY_SIZE * mft_entry_idx), MFT_ENTRY_SIZE)

    """Read an MFT entry.
    """
    def read_mft_entry(self, mft_entry_idx: int) -> bytes:
        mft_entry_raw   = self._read_mft_entry(mft_entry_idx)
        mft_entry  = MFT(mft_entry_raw)
        return mft_entry

    """Get MFT start offset and begin analysis.
    """
    def analyze_ntfs_header(self):
        self.mft_start  = self.ntfs_header["mft_lcn"]
        #print(hex(self.mft_start))
        #print(self.read_mft_entry(0))

        # LAST UPDATE
        self._analyze_mft()

        #print(self._read_cluster(self.mft_start))

    def _extract_file(self):
        pass

    def _analyze_mft(self):
        print("[?] Analyzing MFT")
        mft_file = self.read_mft_entry(0)
        print(mft_file.raw)
        mft_file.parse_mft_header()
        mft_file.parse_attr_header()

        print(mft_file.attributes)

        # offset of attributes from record content
        #ptr = mft_file["attrs_offset"]

        #atr_record = 

        #print(mft_file.mft_parsed)

    def _analyze_registry(self):
        print("[?] Analyzing registries")

    def _analyze_winsec(self):
        print("[?] Analyzing Windows Security")

class MFT(object):
    def __init__(self, header: bytes) -> None:
        self._mft_fields    = [
            "magic", "usa_ofs", "usa_count", "lsn", "sequence_number", "link_count",
            "attrs_offset", "flags", "bytes_in_use", "bytes_allocated", "base_mft_record",
            "next_attr_instance", "reserved", "mft_record_number", "record"
        ]

        self._attr_r_fields   = [
            "type", "length", "non_resident", "name_length", "name_offset",
            "flags", "instance", "value_length", "value_offset", "flags", "reserved"
        ]

        self._attr_nr_fields   = [
            "type", "length", "non_resident", "name_length", "name_offset",
            "flags", "instance", "lowest_vcn", "highest_vcn", "mapping_pairs_offset",
            "compression_unit", "reserved", "allocated_size", "data_size",
            "initialized_size", "compressed_size"
        ]

        self.raw    = header
        # mft header fields with their values
        self.mft_parsed = {}

    def _analyze_attribute(self, attr_parsed: dict):
        if attr_parsed['type'] == 0x10:
            print("Stardard Information:\n++Type: %s Length: %d Resident: %s Name Len:%d Name Offset: %d" % (
                hex(int(attr_parsed['type'])),
                attr_parsed['length'],
                attr_parsed['non_resident'],
                attr_parsed['name_length'],
                attr_parsed['name_offset'],
            ))
        print("ypyp")

    def parse_attr_header(self):
        attrs_offset    = self.mft_parsed["attrs_offset"]

        self.attributes = []
        
        while attrs_offset < 1024:
            attr_parsed = {}

            # used to know if it's a resident (b0) or non-resident (b1) attribute
            attr_record     = self.raw[attrs_offset:]

            if unpack_from(ATTR_RECORD_T, attr_record)[2]:
                buf = unpack_from(ATTR_RECORD_NON_RESIDENT, attr_record)
                for (field, value) in zip(self._attr_nr_fields, buf):
                    attr_parsed.update({field : value})
            else:
                buf = unpack_from(ATTR_RECORD_RESIDENT, attr_record)
                for (field, value) in zip(self._attr_r_fields, buf):
                    attr_parsed.update({field : value})

            if attr_parsed["type"] == 0xffffffff:
                print("[?] Attributes end")
                break

            # if an attribute has a name
            if attr_parsed["name_length"] > 0:
                record_name = self.raw[
                    attrs_offset + attr_parsed["name_offset"]:attrs_offset + attr_parsed["name_offset"] + attr_parsed["name_length"] * 2
                ]
                attr_parsed["name"] = record_name.decode("utf-16").encode()
            else:
                attr_parsed["name"] = ''

            # analyze attribute type
            self._analyze_attribute(attr_parsed)

            self.attributes.append(attr_parsed)
            attrs_offset += attr_parsed["length"]

    def parse_mft_header(self):
        for (field, value) in zip(self._mft_fields, unpack_from(MFT_RECORD_T, self.raw)):
            self.mft_parsed.update({field : value})
        if self.mft_parsed["magic"] != 0x454c4946:
            print("[!] Bad MFT entry")

class NTFSHeader(object):
    def __init__(self, header: bytes) -> None:
        self._fields = [
            "jump", "oem_id", "bytes_per_sector", "sectors_per_cluster",
            "reserved_sectors", "fats", "root_entries", "sectors", "media_type",
            "sectors_per_fat", "sectors_per_track", "heads", "hidden_sectors",
            "large_sectors", "unused", "number_of_sectors", "mft_lcn", "mftmirr_lcn",
            "clusters_per_mft_record", "reserved0", "clusters_per_index_record",
            "reserved1", "volume_serial_number", "checksum", "bootstrap", "end_of_sector_marker"
        ]

        self.header = header
        self.ntfs_header = {}

        for (field, value) in zip(self._fields, unpack(NTFS_BOOT_SECTOR_T, self.header)):
            self.ntfs_header.update({field : value})
