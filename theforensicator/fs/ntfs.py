"""Parser for NTFS"""

import datetime
import json
import re
from struct import unpack, unpack_from
from os.path import normpath, isfile
from os import unlink

import theforensicator

SECTOR_SIZE = 512

def SECTOR_NB(x):
    return x // SECTOR_SIZE

BIOS_PARAMETER_BLOCK_T = "HBHBHHBHHHII"
NTFS_BOOT_SECTOR_T = "<3sQ" + BIOS_PARAMETER_BLOCK_T + "IQQQB3sB3sQI426sH"

MFT_HEADER_SIZE = 48
MFT_ENTRY_SIZE = 1024
MFT_RECORD_T = f"<IHHQHHHHIIQHHI{MFT_ENTRY_SIZE - MFT_HEADER_SIZE}s"

# Attribute record type
ATTR_RECORD_T = "IIBBHHH"
ATTR_RECORD_RESIDENT = ATTR_RECORD_T + "IHBB"
ATTR_RECORD_NON_RESIDENT = ATTR_RECORD_T + "QQHB5sQQQQ"

# MFT entry flags
FILE_RECORD_SEGMENT_IN_USE = 0x1  # In use
MFT_RECORD_IN_USE = FILE_RECORD_SEGMENT_IN_USE

FILE_NAME_INDEX_PRESENT = 0x2  # Has file name (or $I30) index
MFT_RECORD_IS_DIRECTORY = FILE_NAME_INDEX_PRESENT  # When this flag is set the file entry represents a directory (that contains sub file entries)

MFT_RECORD_IN_EXTEND = 0x4  # According to [APPLE06] this is set for all system files present in the $Extend directory

MFT_RECORD_IS_VIEW_INDEX = (
    0x8  # When this flag is set the file entry represents an index
)
# According to [APPLE06] this is set for all indices other than $I30

FILE_MFT = 0  # Master file table (mft). Data attribute contains the entries and bitmap attribute records which ones are in use (bit==1).
FILE_MFTMirr = 1  # Mft mirror: copy of first four mft records in data attribute. If cluster size > 4kiB, copy of first N mft records, with N = cluster_size / mft_record_size.
FILE_LogFile = 2  # Journalling log in data attribute.
FILE_Volume = 3  # Volume name attribute and volume information attribute (flags and ntfs version). Windows refers to this file as volume DASD (Direct Access Storage Device).
FILE_AttrDef = 4  # Array of attribute definitions in data attribute.
FILE_root = 5  # Root directory.
FILE_Bitmap = 6  # Allocation bitmap of all clusters (lcns) in data attribute.
FILE_Boot = 7  # Boot sector (always at cluster 0) in data attribute.
FILE_BadClus = 8  # Contains all bad clusters in the non-resident data attribute.
FILE_Secure = (
    9,
)  # Shared security descriptors in data attribute and two indexes into the descriptors. Appeared in Windows 2000. Before that, this file was named $Quota but was unused.
FILE_UpCase = (
    10,
)  # Uppercase equivalents of all 65536 Unicode characters in data attribute.
FILE_Extend = (
    11,
)  # Directory containing other system files (eg. $ObjId, $Quota, $Reparse and $UsnJrnl). This is new to NTFS3.0.
FILE_reserved12 = (12,)  # Reserved for future use (records 12-15).
FILE_reserved13 = (13,)
FILE_reserved14 = (14,)
FILE_reserved15 = (15,)
FILE_first_user = 16  # First user file, used as test limit for whether to allow opening a file or not.

AT_UNUSED = 0x0
AT_STANDARD_INFORMATION = 0x10
AT_ATTRIBUTE_LIST = 0x20
AT_FILE_NAME = 0x30
AT_OBJECT_ID = 0x40
AT_SECURITY_DESCRIPTOR = 0x50
AT_VOLUME_NAME = 0x60
AT_VOLUME_INFORMATION = 0x70
AT_DATA = 0x80
AT_INDEX_ROOT = 0x90
AT_INDEX_ALLOCATION = 0xA0
AT_BITMAP = 0xB0
AT_REPARSE_POINT = 0xC0
AT_EA_INFORMATION = 0xD0
AT_EA = 0xE0
AT_PROPERTY_SET = 0xF0
AT_LOGGED_UTILITY_STREAM = 0x100
AT_FIRST_USER_DEFINED_ATTRIBUTE = 0x1000
AT_END = 0xFFFFFFFF

READ_ONLY = 0x0001
HIDDEN = 0x0002
SYSTEM = 0x0004
ARCHIVE = 0x0020
DEVICE = 0x0040
NORMAL = 0x0080
TEMPORARY = 0x0100
SPARSE_FILE = 0x0200
REPARSE_POINT = 0x0400
COMPRESSED = 0x0800
OFFLINE = 0x1000
NOT_INDEXED = 0x2000
ENCRYPTED = 0x4000
DIRECTORY = 0x10000000
INDEX_VIEW = 0x20000000


class NTFS(object):
    """NTFS class"""

    def __init__(self, ewf_image: "theforensicator.app.EWFImage", partition) -> None:
        """Initializes the NTFS object

        Args:
            ewf_image: EWF object we are based on
            partition: Partition we will parse
        """
        self.ewf_image = ewf_image

        self.handle = self.ewf_image.handle
        self.verbose = self.ewf_image.verbose
        self.partition = partition
        self._start = self.partition["first_lba"]
        self._end = self.partition["last_lba"]

        self.is_mft_dump = None
        self.dump_mft = None

        self.handle.seek(self._start * SECTOR_SIZE)
        self.ntfs_header = NTFSHeader(
            self._read_nsectors(0, SECTOR_NB(SECTOR_SIZE))
        ).ntfs_header
        self.cluster_block_size = (
            self.ntfs_header["bytes_per_sector"]
            * self.ntfs_header["sectors_per_cluster"]
        )

        print("[+] NTFS partition at sector %#x" % (self._start))

        if self.verbose:
            pass
            #self._pretty_print()

        self.mft = {}

    def _pretty_print(self):
        """Prints additionnal informations about the partition"""

        for header_name in self.ntfs_header.keys():
            if type(self.ntfs_header[header_name]) is bytes or str:
                print("\t%-18s : %s" % (header_name, self.ntfs_header[header_name]))
            else:
                print("\t%-20s : %#x" % (header_name, self.ntfs_header[header_name]))

        print("=" * 0x40)

    def _read(self, offset: int, nb_bytes: int) -> bytes:
        """Reads data at a given offset

        Args:
            offset: Where we want to read
            nb_bytes: Number of bytes we want to read

        Returns:
            The bytes we have read
        """
        curr_off = self.handle.get_offset()
        self.handle.seek(self._start * SECTOR_SIZE + offset)
        buf = self.handle.read(nb_bytes)
        self.handle.seek(curr_off)
        return buf

    def _read_sector(self, sector_idx: int) -> bytes:
        """Reads the given sector

        Args:
            sector_idx: Index of the sector we want to read

        Returns:
            The bytes we have read
        """
        return self._read(sector_idx * SECTOR_SIZE, SECTOR_SIZE)

    def _read_nsectors(self, sector_idx: int, nb_sector: int) -> bytes:
        """Reads the given sectors

        Args:
            sector_idx: Index of the first sector we want to read
            nb_sector: Number of sectors we want to read

        Returns:
            The bytes we have read
        """
        return self._read(sector_idx * SECTOR_SIZE, nb_sector * SECTOR_SIZE)

    def _read_cluster(self, cluster_idx: int) -> bytes:
        """Reads a cluster

        Args:
            cluster_idx: Index of the cluster we want to read

        Returns:
            The bytes we have read
        """
        return self._read(
            cluster_idx * self.cluster_block_size, self.cluster_block_size
        )

    def _read_cluster_nbytes(self, cluster_idx: int, nb_bytes: int) -> bytes:
        """Reads some bytes from a cluster

        Args:
            cluster_idx: Index of the cluster we want to read
            nb_bytes: Number of bytes to read

        Returns:
            The bytes we have read
        """
        return self._read(cluster_idx * self.cluster_block_size, nb_bytes)

    def _read_mft_entry(self, mft_entry_idx: int):
        """Reads a MFT entry

        Args:
            mft_entry_idx: Index of the mft entry we want to read

        Returns:
            The bytes we have read
        """
        return self._read(
            (self.mft_start * self.cluster_block_size)
            + (MFT_ENTRY_SIZE * mft_entry_idx),
            MFT_ENTRY_SIZE,
        )

    def read_mft_entry(self, mft_entry_idx: int, verbose=False) -> bytes:
        """Reads a MFT entry

        Args:
            mft_entry_idx: Index of the mft entry we want to read
            verbose: How much logs we want

        Returns:
            The bytes we have read
        """
        mft_entry_raw = self._read_mft_entry(mft_entry_idx)
        mft_entry = MFT(mft_entry_raw, self, verbose)
        return mft_entry

    def load_mft_dump(self, dump_file: str):
        """Load a MFT dump

        Args:
            dump_file: Path of the dump
        """
        with open(dump_file, "r") as dmp_file:
            self.dump_mft = json.loads(dmp_file.read())
            dmp_file.close()

    def analyze_ntfs_header(self, partition_idx: str, resolve_mft_file: str, clear_cache):
        """Analyze the NTFS header

        Args:
            out_file: Where to store the output
            dump_file: Where the output has been stored in a previous run
            resolve_mft_file: Where the resolved MFT in JSON format will be stored
        """
        mft_dump_filepath = f"MFT{partition_idx}.dump"

        if clear_cache:
            if isfile(mft_dump_filepath):
                unlink(mft_dump_filepath)
                print("[+] Cache cleared.")

        self.mft_start = self.ntfs_header["mft_lcn"]

        print("[+] Loading and analyzing MFT ...")

        if not isfile(mft_dump_filepath):
            self.is_mft_dump = False
            self.analyze_mft(mft_dump_filepath)
        else:
            print("[+] Found %s, loading cache file." % (mft_dump_filepath))
            self.is_mft_dump = True
            self.load_mft_dump(mft_dump_filepath)
            print("[+] Cache file loaded.")

        print("[+] MFT loaded ...")

        self.resolve_mft(resolve_mft_file)

    def _get_dump_mft_entry(self, idx: int):
        """Get a dump of the given mft entry

        Args:
            Index of the MFT entry to dump
        """
        return (
            self.dump_mft["mft"][str(idx)]
            if self.is_mft_dump
            else self.dump_mft["mft"][idx]
        )

    def _resolve_path(self, mft_entry) -> list:
        """Resolve the path of the given mft entry

        Args:
            mft_entry: MFT entry to resolve

        Returns:
            The list of the possible paths of the MFT entry
        """
        paths = []

        # if it's a directory
        if mft_entry["is_directory"]:
            path = ""
            parent_dir = mft_entry["parent_directory"]
            path += mft_entry["directory_name"]

            while parent_dir != FILE_root:
                next_entry = self._get_dump_mft_entry(parent_dir)

                if next_entry["is_directory"]:
                    parent_dir = next_entry["parent_directory"]
                    path = f'{next_entry["directory_name"]}\\{path}'
                else:
                    return [{"type": "ORPHAN_DIRECTORY", "directory_name": path}]

            path = "C:\\" + path

            paths.append({"type": "DIRECTORY", "directory_name": path})
        else:
            for file in mft_entry["files"]:
                path = ""
                parent_dir = file["parent_directory"]
                path += file["file_name"]

                while parent_dir != FILE_root:
                    next_entry = self._get_dump_mft_entry(parent_dir)

                    if next_entry["is_directory"]:
                        parent_dir = next_entry["parent_directory"]
                        path = f'{next_entry["directory_name"]}\\{path}'
                    else:
                        return [{"type": "ORPHAN_FILE", "file_name": path}]

                path = "C:\\" + path

                paths.append({"type": "FILE", "file_name": path})

        return paths

    def resolve_mft(self, json_outfile: str):
        """Resolve the MFT paths and save it to outfile

        Args:
            json_outfile: Where to save the output
        """
        self.resolved_mft = {}

        print("[+] Resolving paths from MFT ...")

        for entry_idx in self.dump_mft["mft"].keys():
            entry = self._get_dump_mft_entry(entry_idx)
            path_infos = self._resolve_path(entry)

            if path_infos:
                obj_type = path_infos[0]["type"]
                if obj_type in ["DIRECTORY", "ORPHAN_DIRECTORY"]:
                    self.resolved_mft[int(entry_idx)] = {
                        "type": obj_type,
                        "info": path_infos,
                        "dates": entry["dates"],
                    }

                if obj_type in ["FILE", "ORPHAN_FILE"]:
                    # case not handled in AT_DATA attribute
                    data = None

                    if "data" in entry:
                        data = entry["data"]
                    else:
                        # need to fix this issue
                        pass

                    self.resolved_mft[int(entry_idx)] = {
                        "type": obj_type,
                        "info": path_infos,
                        "dates": entry["dates"],
                        "data": data,
                    }

        print("[+] MFT paths resolved ...")

        if json_outfile and type(json_outfile) is str:
            with open(json_outfile, "w") as dmp:
                dmp.write(json.dumps(self.resolved_mft))
                dmp.close()
            print("[+] %s successfully written." % (json_outfile))

    def analyze_mft(self, out_file: str):
        """Analyze the MFT

        Args:
            out_file: Where to store the output
        """
        print("[?] Analyzing MFT")

        mft_entry_nb = -1

        while True:
            mft_entry_nb += 1

            mft_file = self.read_mft_entry(mft_entry_nb, verbose=False)
            # print(f"Reading MFT entry {mft_entry_nb}")

            if mft_file.raw[0:4] == b"\x00" * 4:
                continue

            mft_file.parse_mft_header()

            if not mft_file.is_valid_entry:
                break

            mft_file.parse_attr_header()

            self.mft[mft_entry_nb] = mft_file.record

        self.dump_mft = {
            "disk_filename": self.ewf_image.filename,
            "total_entries": mft_entry_nb,
            "mft": self.mft,
        }

        with open(out_file, "w") as dmp_file:
            dmp_file.write(json.dumps(self.dump_mft))
            dmp_file.close()

    def _dump_data(self, lcn_dict: dict) -> bytes:
        raw_data = lcn_dict["raw_data"]

        buf = b""

        if lcn_dict["size"] == 0 and len(raw_data) == 0:
            return b""

        if type(raw_data) is str:
            return bytes.fromhex(raw_data)

        for lcn in raw_data:
            for idx in range(lcn["lcn_length"]):
                buf += self._read_cluster(lcn["lcn_offset"] + idx)

        return buf[: lcn_dict["init_size"]]

    def write_to_file(self, dump_dir, filename: str, data: bytes):
        if dump_dir and type(dump_dir) is str:
            out_filename = normpath(dump_dir + "/dump_" + filename.replace('\\', '_').replace(':', ''))
        else:
            out_filename = "./dump_" + filename.replace('\\', '_').replace(':', '')

        with open(out_filename, "wb") as f:
            f.write(data)
            f.close()

        print("[?] %s successfully dumped to %s." % (filename, out_filename))

    def dump_file(self, filenames: list, dump_dir: str) -> bytes:
        """Dump a file using its filename

        Args:
            filenames: Filename of the file to dump

        Returns:
            The file content
        """

        files_list_match = '(?:%s)' % '|'.join(filenames)

        for key in self.resolved_mft:
            
            obj_type = self.resolved_mft[key]["type"]

            if obj_type not in ["FILE", "ORPHAN_FILE"]:
                continue

            info = self.resolved_mft[key]["info"]

            for file in info:
                if re.match(files_list_match, file["file_name"], flags=re.IGNORECASE):
                    data = self.resolved_mft[key]["data"]
                    if data:
                        self.write_to_file(
                            dump_dir,
                            file["file_name"],
                            self._dump_data(data)
                        )

    def _analyze_registry(self):
        print("[?] Analyzing registries")

    def _analyze_winsec(self):
        print("[?] Analyzing Windows Security")


class MFT(object):
    """MFT class"""

    def __init__(self, header: bytes, ntfs: "NTFS", verbose: bool) -> None:
        """Initialize the MFT class

        Args:
            header: Header of the MFT
            ntfs: NTFS
            verbose: verbose
        """
        self._mft_fields = [
            "magic",
            "usa_ofs",
            "usa_count",
            "lsn",
            "sequence_number",
            "link_count",
            "attrs_offset",
            "flags",
            "bytes_in_use",
            "bytes_allocated",
            "base_mft_record",
            "next_attr_instance",
            "reserved",
            "mft_record_number",
            "record",
        ]

        self._attr_r_fields = [
            "type",
            "length",
            "non_resident",
            "name_length",
            "name_offset",
            "flags",
            "instance",
            "value_length",
            "value_offset",
            "flags",
            "reserved",
        ]

        self._attr_nr_fields = [
            "type",
            "length",
            "non_resident",
            "name_length",
            "name_offset",
            "flags",
            "instance",
            "lowest_vcn",
            "highest_vcn",
            "mapping_pairs_offset",
            "compression_unit",
            "reserved",
            "allocated_size",
            "data_size",
            "initialized_size",
            "compressed_size",
        ]

        self.raw = header
        self.ntfs = ntfs
        self.verbose = verbose

        # mft header fields with their values
        self.mft_parsed = {}
        self.is_valid_entry = True
        self.record = {"is_directory": False, "files": []}

    def _get_datetime(self, windows_time: int) -> dict:
        """Convert windows time to datetime

        Args:
            windows_time: Time to convert

        Returns:
            Time in a dict
        """
        seconds = windows_time / 10000000
        epoch = seconds - 11644473600
        
        if epoch < 0:
            epoch = 0
        
        dt = datetime.datetime(2000, 1, 1, 0, 0, 0).fromtimestamp(epoch)
        return {"timestamp": epoch, "date": f"{dt.ctime()}"}

    """Attribute type : (0x10) STANDARD_INFORMATION.
    """

    def _standard_info_decode(self, attribute: bytes):
        """Decode STANDARD_INFORMATION attribute

        Args:
            attribute: Raw attribute to decode
        
        Returns:
            The parsed attribute
        """
        # not complete but at this time we don't need more
        si_info = {}

        si_info["creation_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x0)[0]
        )
        si_info["last_data_change_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x8)[0]
        )
        si_info["last_mft_change_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x10)[0]
        )
        si_info["last_access_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x18)[0]
        )
        si_info["file_attributes"] = unpack_from("<I", attribute, offset=0x20)[0]

        if self.verbose:
            print(
                "-> Created : %s\n-> Last data change : %s\n-> Last MFT change : %s\n-> Last access : %s\n-> Flags : %d"
                % (
                    si_info["creation_time"]["date"],
                    si_info["last_data_change_time"]["date"],
                    si_info["last_mft_change_time"]["date"],
                    si_info["last_access_time"]["date"],
                    si_info["file_attributes"],
                )
            )

        return si_info

    """Attribute type : (0x20) ATTR_LIST_ENTRY.
    """

    def _attribute_list_decode(self, attribute: bytes) -> dict:
        """Decode ATTR_LIST_ENTRY attribute

        Args:
            attribute: Raw attribute to decode
        
        Returns:
            The parsed attribute
        """
        attr_list = {}

        attr_list["type"] = unpack_from("<I", attribute, offset=0)[0]
        attr_list["length"] = unpack_from("<H", attribute, offset=4)[0]
        attr_list["name_length"] = unpack_from("<B", attribute, offset=6)[0]
        attr_list["name_offset"] = unpack_from("<B", attribute, offset=7)[0]
        attr_list["lowest_vcn"] = unpack_from("<Q", attribute, offset=8)[0]
        attr_list["mft_reference"] = unpack_from("<Q", attribute, offset=16)[0]
        attr_list["instance"] = unpack_from("<H", attribute, offset=24)[0]
        attr_list["name"] = unpack_from(
            f"<{attr_list['name_length'] * 2}s", attribute, offset=26
        )[0]

        return attr_list

    """Attribute type : (0x30) FILE_NAME_ATTR
    A file can be an archive, the flags field tells us if it's the case.
    """

    def _file_name_decode(self, attribute: bytes) -> dict:
        """Decode FILE_NAME_ATTR attribute

        Args:
            attribute: Raw attribute to decode
        
        Returns:
            The parsed attribute
        """
        _file_name = {}

        # for now there's no check on sequence number, maybe after
        # it's used to know either the file is allocated, deleted or orphan
        # https://usermanual.wiki/Pdf/WpNtOrphanFilesEnUs.1012197800.pdf
        parent_dir = unpack_from("<Q", attribute, offset=0x0)[0]
        _file_name["parent_directory"] = parent_dir & 0xFFFFFFFFFFFF
        _file_name["seq_num"] = parent_dir >> 0x30
        _file_name["creation_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x8)[0]
        )
        _file_name["last_data_change_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x10)[0]
        )
        _file_name["last_mft_change_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x18)[0]
        )
        _file_name["last_access_time"] = self._get_datetime(
            unpack_from("<Q", attribute, offset=0x20)[0]
        )
        _file_name["allocated_size"] = unpack_from("<Q", attribute, offset=0x28)[0]
        _file_name["data_size"] = unpack_from("<Q", attribute, offset=0x30)[0]
        _file_name["file_attributes"] = unpack_from("<I", attribute, offset=0x38)[0]
        # some are missing because not useful at this time
        _file_name["file_name_length"] = unpack_from("<B", attribute, offset=0x40)[0]
        _file_name["file_name_type"] = unpack_from("<B", attribute, offset=0x41)[0]
        _file_name["file_name"] = unpack_from(
            f"<{_file_name['file_name_length'] * 2}s", attribute, offset=0x42
        )[0].decode("utf-16")

        self.record["dates"] = {
            "creation_time": _file_name["creation_time"],
            "last_data_change_time": _file_name["last_data_change_time"],
            "last_mft_change_time": _file_name["last_mft_change_time"],
            "last_access_time": _file_name["last_access_time"],
        }

        if _file_name["file_attributes"] & DIRECTORY == DIRECTORY:
            self.record["is_directory"] = True
            self.record["directory_name"] = _file_name["file_name"]
            self.record["parent_directory"] = _file_name["parent_directory"]
            self.record["seq_num"] = _file_name["seq_num"]

        else:
            if (_file_name["file_attributes"] & ARCHIVE) == ARCHIVE:
                _file_name["is_archive"] = True

            if (_file_name["file_attributes"] & COMPRESSED) == COMPRESSED:
                pass
                # print("COMPRESSED FILE FOUND !")
                # exit()

            self.record["files"].append(_file_name)

        if self.verbose:
            print("Filename record")
            print(
                "-> Parent directory : %d"
                % (_file_name["parent_directory"] & 0xFFFFFFFFFFFF)
            )
            print("-> Name : %s" % (_file_name["file_name"]))
            print("-> Creation : %s" % (_file_name["creation_time"]["date"]))
            print(
                "-> Last data change : %s"
                % (_file_name["last_data_change_time"]["date"])
            )
            print(
                "-> Last MFT change : %s" % (_file_name["last_mft_change_time"]["date"])
            )
            print("-> Last access : %s" % (_file_name["last_access_time"]["date"]))
            print("-> Size : %d" % _file_name["data_size"])
            print("-> Flags : %#x" % _file_name["file_attributes"])

        return _file_name

    """Attribute type : (0x40) OBJECT_ID_ATTR
    """

    def _object_id_decode(self, attribute: bytes) -> dict:
        """Decode OBJECT_ID_ATTR attribute

        Args:
            attribute: Raw attribute to decode
        
        Returns:
            The parsed attribute
        """
        _object_id = {}

        _object_id["data1"] = unpack_from("<I", attribute, offset=0x0)[0]
        _object_id["data2"] = unpack_from("<H", attribute, offset=0x4)[0]
        _object_id["data3"] = unpack_from("<H", attribute, offset=0x6)[0]
        _object_id["data4"] = unpack_from("<8s", attribute, offset=0x8)[0]

        #         guid = "%08x-%04x-%04x-%s" % (
        #             _object_id["data1"],
        #             _object_id["data2"],
        #             _object_id["data3"],
        #             _object_id["data4"].hex(),
        #         )

        # print("GUID : %s" % guid)

        return _object_id

    """Attribute type : (0x60) VOLUME_NAME
    """

    def _volume_name_decode(self, attribute: bytes):
        # _volume_name = {}
        pass

    """Attribute type : (0x80) DATA
    """

    def _data_runs_decode(self, dataruns: bytes) -> list:
        """Decode DATA attribute

        Args:
            dataruns: dataruns list
        
        Returns:
            Data of the MFT entry
        """
        current_datarun = dataruns
        run_header = unpack_from("<B", current_datarun, offset=0)[0]

        data = []

        size_lcn_nb = run_header & 0xF
        size_lcn_offset = run_header >> 4

        lcn_length = unpack("<Q", current_datarun[1 : 1 + size_lcn_nb].ljust(8, b"\0"))[
            0
        ]
        lcn_offset = unpack(
            "<Q",
            current_datarun[1 + size_lcn_nb : 1 + size_lcn_nb + size_lcn_offset].ljust(
                8, b"\0"
            ),
        )[0]

        if lcn_length == 0x0:
            print("ERROR SPARSE FILE !")
            exit()

        # used for relative offset
        prev_offset = lcn_offset

        data.append({"lcn_length": lcn_length, "lcn_offset": lcn_offset})

        current_datarun = current_datarun[1 + size_lcn_nb + size_lcn_offset :]

        # potential next datarun
        run_header = unpack_from("<B", current_datarun, offset=0)[0]

        # if we enter in the loop, it means that the file is
        # fragmented or sparsed (empty VCN between clusters)
        while (run_header != 0x0) and ((run_header & 0xF) < 0x4):
            size_lcn_nb = run_header & 0xF
            size_lcn_offset = run_header >> 4

            # print(current_datarun)

            lcn_length = unpack(
                "<Q", current_datarun[1 : 1 + size_lcn_nb].ljust(8, b"\0")
            )[0]
            lcn_offset = unpack(
                "<Q",
                current_datarun[
                    1 + size_lcn_nb : 1 + size_lcn_nb + size_lcn_offset
                ].ljust(8, b"\0"),
            )[0]

            # if it's a sparse file we continue to the next
            # run because we don't care of this data.
            if lcn_length == 0x0:
                pass
                # print("sparse file")
            else:
                # if not sparsed we add data

                # if signed bit
                if (lcn_offset >> 23) & 1 == 1:
                    lcn_offset = (
                        int(bin(lcn_offset)[2:].rjust(32, "1"), 2) % -0x100000000
                    )

                data.append(
                    {"lcn_length": lcn_length, "lcn_offset": (prev_offset + lcn_offset)}
                )

            prev_offset = prev_offset + lcn_offset
            current_datarun = current_datarun[1 + size_lcn_nb + size_lcn_offset :]
            run_header = unpack_from("<B", current_datarun, offset=0)[0]

        return data

    def _analyze_attribute(self, attr_parsed: dict, raw_attr: bytes):
        """Analyze and decode an attribute

        Args:
            attr_parsed: parsed attribute dict
            raw_attr: raw bytes attribute
        """
        if attr_parsed["non_resident"]:
            attribute = b""
        else:
            attribute = raw_attr[attr_parsed["value_offset"] :]

        if attr_parsed["type"] == AT_STANDARD_INFORMATION:
            si_info = self._standard_info_decode(
                raw_attr[attr_parsed["value_offset"] :]
            )

        # not checked
        if attr_parsed["type"] == AT_ATTRIBUTE_LIST:
            if attr_parsed["non_resident"] == 0:
                attr_list = self._attribute_list_decode(attribute)
            else:
                # TO FIX
                # we can fall in this case if there's not enough place
                # for data runs. (see: https://flatcap.github.io/linux-ntfs/ntfs/attributes/attribute_list.html)
                # print(attr_parsed)
                # print(raw_attr[attr_parsed['mapping_pairs_offset']:])
                # print("Non-resident attribute list")
                # exit()
                pass

        if attr_parsed["type"] == AT_FILE_NAME:
            _file_name = self._file_name_decode(attribute)

        if attr_parsed["type"] == AT_OBJECT_ID:
            object_id = self._object_id_decode(attribute)

        if attr_parsed["type"] == AT_VOLUME_NAME:
            volume_name = self._volume_name_decode(attribute)

        if attr_parsed["type"] == AT_DATA:
            if attr_parsed["name"] != "":
                pass
                # print("AT_DATA ERROR")
                # exit()

            """
            If the attribute is resident, then data is stored in the attribute
            """
            if attr_parsed["non_resident"] == 0:
                data = raw_attr[
                    attr_parsed["value_offset"] : attr_parsed["value_offset"]
                    + attr_parsed["value_length"]
                ]
                self.record["raw_data"] = True
                self.record["data"] = {
                    "size": attr_parsed["value_length"],
                    "raw_data": data.hex(),
                }

            """
            If the attribute is non-resident, then data is stored somewhere in memory,
            we can know location based on dataruns stored at the end of the attribute.
            """
            if attr_parsed["non_resident"] == 1:
                """
                data_run structure :
                    - header : constructed of 1 byte (ex: 0x21)
                        -> header & 0xf = size of number of clusters
                        -> header >> 4  = offset to starting cluster number (LCN)
                """

                if attr_parsed["allocated_size"] > 0:
                    # `mapping_pairs_offset` is the offset from attribute start of dataruns
                    data = self._data_runs_decode(
                        raw_attr[attr_parsed["mapping_pairs_offset"] :]
                    )

                    self.record["raw_data"] = False
                    self.record["data"] = {
                        "size": attr_parsed["data_size"],
                        "init_size": attr_parsed["initialized_size"],
                        "raw_data": data,
                    }

    """This function will parse attribute header of an MFT entry.
    """

    def parse_attr_header(self):
        """Parse an attribute
        """
        attrs_offset = self.mft_parsed["attrs_offset"]

        # offset must be aligned on 8 bytes
        if attrs_offset % 8:
            print("Attribute misalignment")

        self.attributes = []

        while attrs_offset < 1024:
            attr_parsed = {}

            # used to know if it's a resident (b0) or non-resident (b1) attribute
            attr_record = self.raw[attrs_offset:]

            if unpack_from("<I", attr_record, offset=0)[0] == 0xFFFFFFFF:
                # print("[?] Attributes end")
                break

            if unpack_from(ATTR_RECORD_T, attr_record)[2]:
                buf = unpack_from(ATTR_RECORD_NON_RESIDENT, attr_record)
                for (field, value) in zip(self._attr_nr_fields, buf):
                    attr_parsed.update({field: value})
            else:
                buf = unpack_from(ATTR_RECORD_RESIDENT, attr_record)
                for (field, value) in zip(self._attr_r_fields, buf):
                    attr_parsed.update({field: value})

            # if an attribute has a name
            if attr_parsed["name_length"] > 0:
                record_name = attr_record[
                    attr_parsed["name_offset"] : attr_parsed["name_offset"]
                    + (attr_parsed["name_length"] * 2)
                ]
                attr_parsed["name"] = record_name.decode("utf-16").encode()
            else:
                attr_parsed["name"] = ""

            # analyze attribute type
            self._analyze_attribute(attr_parsed, attr_record)

            self.attributes.append(attr_parsed)

            attrs_offset += attr_parsed["length"]

        # maybe use this to avoid some calculus above
        self.record["nb_record"] = self.mft_parsed["mft_record_number"]

    """Parse MFT header
    """

    def parse_mft_header(self):
        for (field, value) in zip(
            self._mft_fields, unpack_from(MFT_RECORD_T, self.raw)
        ):
            self.mft_parsed.update({field: value})

        # check if it's a valid MFT entry
        if self.mft_parsed["magic"] != 0x454C4946:
            self.is_valid_entry = False
            # print("Bad magic :", hex(self.mft_parsed["magic"]))
            # print("Entry number : %d" % self.mft_parsed["mft_record_number"])
            # print("[!] Bad MFT entry")
            # exit()


class NTFSHeader(object):
    """NTFS Header"""

    def __init__(self, header: bytes) -> None:
        """Initialize the NTFSHeader class

        Args:
            header: Bytes of the header
        """
        self._fields = [
            "jump",
            "oem_id",
            "bytes_per_sector",
            "sectors_per_cluster",
            "reserved_sectors",
            "fats",
            "root_entries",
            "sectors",
            "media_type",
            "sectors_per_fat",
            "sectors_per_track",
            "heads",
            "hidden_sectors",
            "large_sectors",
            "unused",
            "number_of_sectors",
            "mft_lcn",
            "mftmirr_lcn",
            "clusters_per_mft_record",
            "reserved0",
            "clusters_per_index_record",
            "reserved1",
            "volume_serial_number",
            "checksum",
            "bootstrap",
            "end_of_sector_marker",
        ]

        self.header = header
        self.ntfs_header = {}

        for (field, value) in zip(
            self._fields, unpack(NTFS_BOOT_SECTOR_T, self.header)
        ):
            if field == "bootstrap":
                self.ntfs_header[field] = value.hex()
            else:
                self.ntfs_header.update({field: value})
