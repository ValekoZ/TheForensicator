"""
minimal EWF "driver" in pure Python
Laurent Clevy (@lorenzo2472)

reference document : https://github.com/libyal/libewf/blob/master/documentation/Expert%20Witness%20Compression%20Format%20%28EWF%29.asciidoc
tested with FTK imager 4.3 and Ewfacquire
"""

import argparse
import array
import sys
from binascii import hexlify
from collections import namedtuple
from hashlib import md5, sha1, sha256
from pathlib import Path, PurePath
from struct import Struct
from zlib import adler32, decompress


class Ewf:
    S_HEADER = Struct("<8sBHH")
    NT_HEADER = namedtuple("header", "signature one segment_num zero")
    assert S_HEADER.size == 13

    S_SECTION = Struct("<16sQQ40sL")
    NT_SECTION = namedtuple("section", "stype next_offset size padding checksum")
    assert S_SECTION.size == 76

    S_DISK = Struct("<LLLLL20s45s5sL")
    assert S_DISK.size == 94
    NT_DISK = namedtuple(
        "disk",
        "one chunk_count sectors_per_chunk bytes_per_sector sector_count reserved padding signature checksum",
    )

    S_VOLUME = Struct("<LLLLL")
    NT_VOLUME = namedtuple(
        "volume", "reserved chunk_count sectors_per_chunk bytes_per_sector sector_count"
    )

    S_TABLE_HEADER = Struct("<L4sQ4sL")
    assert S_TABLE_HEADER.size == 24
    NT_TABLE_HEADER = namedtuple("table_header", "entry_count pad1 base pad2 checksum")

    S_DIGEST = Struct("<16s20s40sL")
    assert S_DIGEST.size == 80
    NT_DIGEST = namedtuple("digest", "md5 sha1 padding checksum")

    S_HASH = Struct("<16s16sL")
    assert S_HASH.size == 36
    NT_HASH = namedtuple("digest", "md5 unknown checksum")

    S_DATA = Struct("<B3sLLLQLLLB3sL4sLB3sL4s16s963s5sL")
    assert S_DATA.size == 1052
    NT_DATA = namedtuple(
        "data",
        "media_type unk1 chunk_count sectors_per_chunk bytes_per_sector sector_count cylinders heads sectors media_flags unk2 PALM_volume unk3 smart_logs compr_level unk4 errors unk5 guid unk6 signature checksum",
    )

    SECTION_HEADER = b"header\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_HEADER2 = b"header2\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_DATA = b"data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_DISK = b"disk\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_VOLUME = b"volume\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_SECTORS = b"sectors\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_TABLE = b"table\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_TABLE2 = b"table2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_DIGEST = b"digest\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    SECTION_HASH = b"hash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    EVF_SIGNATURE = b"EVF\t\r\n\xff\x00"

    def __init__(self, filename, checksums=False, verbose=0):
        self.chunks = dict()  # list of chunks pointers per segment
        self.uncompressed = (
            dict()
        )  # keep track of uncompressed chunks by storing their offset in the segment

        if PurePath(filename).suffix == ".E01":
            filenames = sorted(
                Path(filename).parent.glob(Path(filename).name[:-2] + "??")
            )
            # print( filenames )
            self.current_segment = None  # for seek()
            self.current_chunk_num = 0
            self.ptr_in_current_chunk = 0
            self.current_chunk_data = None
            self.total_chunk_count = 0
            self.checksums = checksums
            self.verbose = verbose

            # data per segment
            self.filedesc = dict()
            self.filename = dict()
            self.hashes = dict()  # to store md5 and sha1
            self.end_of_sectors = (
                dict()
            )  # to known how many bytes to read for last compressed chunk of the segment
            # self.sectors_offset = dict()
            for filename in filenames:
                self.parse_segment(filename)

            self.chunk_range = dict()
            start_chunk = 0
            self.last_sector_in_last_chunk = (
                self.total_chunk_count * self.sectors_per_chunk
            ) - self.sector_count
            # print('self.last_sector_in_last_chunk %x' % self.last_sector_in_last_chunk)
            for i in range(1, self.last_segment + 1):
                end_chunk = start_chunk + len(self.chunks[i]) - 1
                self.chunk_range[i] = (
                    start_chunk,
                    end_chunk,
                )  # determine chunk number range per segment
                start_chunk = end_chunk + 1

            self.seek(0)  # init "file" pointer to 0

        else:
            print("unsupported format")
            sys.exit()

    def parse_header(self, section_nt):
        header_data = self.filedesc[self.last_segment].read(section_nt.size)
        self.header_string = decompress(header_data)
        # FTK imager : b'1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\tr\n \t \tuntitled\t \t \tADI4.3.0.18\tWin 201x\t2020 9 23 10 11 36\t2020 9 23 10 11 36\t0\tf\n'
        # Ewfacquire : b'1\r\nmain\r\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\r\n\t\t\t\t\t20180403\tLinux\t2020 2 6 15 4 33\t2020 2 6 15 4 33\t0\r\n\r\n'
        if self.verbose > 1:
            print(self.header_string)

    def parse_tables(self, section_nt):
        data = self.filedesc[self.last_segment].read(section_nt.size)
        table_header_nt = Ewf.NT_TABLE_HEADER(*Ewf.S_TABLE_HEADER.unpack_from(data, 0))
        if self.verbose > 1:
            print(table_header_nt)
        # print('%x %x' % (Ewf.S_SECTION.size+Ewf.S_TABLE_HEADER.size+table_header_nt.entry_count*4, section_nt.size ) )
        offset = Ewf.S_TABLE_HEADER.size
        for i in range(table_header_nt.entry_count):
            ptr = (
                Struct("<L").unpack_from(data, offset + i * 4)[0] & 0x7FFFFFFF
            )  # most significant bit is compression status
            ptr += table_header_nt.base
            if (
                Struct("<L").unpack_from(data, offset + i * 4)[0] & 0x80000000 == 0
            ):  # most chunks are compressed (bit is set), so we stores uncompressed ptr only
                self.uncompressed[self.last_segment].add(ptr)
            self.chunks[self.last_segment].add(ptr)

        if self.checksums:
            end_of_table = Ewf.S_TABLE_HEADER.size + table_header_nt.entry_count * 4
            if (
                adler32(data[Ewf.S_TABLE_HEADER.size : end_of_table])
                != Struct("<L").unpack_from(data, end_of_table)[0]
            ):
                print("checksum error (table)")

    def parse_part(self, section_nt, file):
        if section_nt.stype == Ewf.SECTION_HEADER:
            self.parse_header(section_nt)
        elif section_nt.stype == Ewf.SECTION_HEADER2:
            data = file.read(section_nt.size)
            # print( decompress( data ).decode('utf16') )
        elif section_nt.stype == Ewf.SECTION_VOLUME:
            data = file.read(section_nt.size)
            volume_nt = Ewf.NT_VOLUME(*Ewf.S_VOLUME.unpack_from(data, 0))
            if self.verbose > 1:
                print(volume_nt)
            self.chunk_count = volume_nt.chunk_count
            self.sectors_per_chunk = volume_nt.sectors_per_chunk
            self.bytes_per_sector = volume_nt.bytes_per_sector
            self.sector_count = volume_nt.sector_count
            self.chunk_size = (
                volume_nt.sectors_per_chunk * volume_nt.bytes_per_sector
            )  # constant
        elif section_nt.stype == Ewf.SECTION_DISK:
            data = file.read(section_nt.size)
            # print(hexlify(data))
            disk_nt = Ewf.NT_DISK(*Ewf.S_DISK.unpack_from(data, 0))
            self.chunk_count = disk_nt.chunk_count
            self.sectors_per_chunk = disk_nt.sectors_per_chunk
            self.bytes_per_sector = disk_nt.bytes_per_sector
            self.sector_count = disk_nt.sector_count
            self.chunk_size = (
                disk_nt.sectors_per_chunk * disk_nt.bytes_per_sector
            )  # constant
            if self.verbose > 1:
                print(disk_nt)
        elif section_nt.stype == Ewf.SECTION_SECTORS:
            # self.sectors_offset[ self.last_segment ] = section_offset #will be used by next table/table2 section
            # print('self.sectors_offset[ self.last_segment ] %x' % self.sectors_offset[ self.last_segment ])
            self.end_of_sectors[self.last_segment] = (
                file.tell() - Ewf.S_SECTION.size + section_nt.size
            )  # end of 'sectors' section, for last 'sectors' section
        elif (
            section_nt.stype == Ewf.SECTION_TABLE
            or section_nt.stype == Ewf.SECTION_TABLE2
        ):
            self.parse_tables(section_nt)
        elif section_nt.stype == Ewf.SECTION_DIGEST:
            data = file.read(section_nt.size)
            digest_nt = Ewf.NT_DIGEST(*Ewf.S_DIGEST.unpack_from(data, 0))
            self.hashes["md5"] = digest_nt.md5
            self.hashes["sha1"] = digest_nt.sha1
            # print( digest_nt )
        elif section_nt.stype == Ewf.SECTION_HASH:
            data = file.read(section_nt.size)
            hash_nt = Ewf.NT_HASH(*Ewf.S_HASH.unpack_from(data, 0))
            self.hashes["md5"] = hash_nt.md5
            # print( hash_nt )
        elif section_nt.stype == Ewf.SECTION_DATA:
            data = file.read(section_nt.size)

    def parse_segment(self, filename):
        if self.verbose > 0:
            print(filename)
        file = open(filename, "rb")
        # parse EVF header
        data = file.read(Ewf.S_HEADER.size)
        header_nt = Ewf.NT_HEADER(*Ewf.S_HEADER.unpack_from(data, 0))
        assert (
            header_nt.one == 1
            and header_nt.zero == 0
            and header_nt.signature == Ewf.EVF_SIGNATURE
        )
        self.chunks[header_nt.segment_num] = set()
        self.uncompressed[header_nt.segment_num] = set()
        self.last_segment = header_nt.segment_num
        self.filedesc[header_nt.segment_num] = file
        self.filename[header_nt.segment_num] = filename
        if self.verbose > 0:
            print(header_nt)

        data = file.read(Ewf.S_SECTION.size)
        section_nt = Ewf.NT_SECTION(*Ewf.S_SECTION.unpack_from(data, 0))
        if self.verbose > 0:
            print(
                "0x%08x: type:%8s next:%x size:%x"
                % (
                    file.tell(),
                    section_nt.stype,
                    section_nt.next_offset,
                    section_nt.size,
                )
            )
        if self.checksums:
            computed_sum = adler32(data[:-4])
            if section_nt.checksum != computed_sum:
                print(
                    "checksum file:%08x != computed:%08x"
                    % (section_nt.checksum, computed_sum)
                )

        previous_next = 0
        if section_nt.stype == Ewf.SECTION_HEADER:
            self.parse_header(section_nt)
        elif section_nt.stype == Ewf.SECTION_DATA:
            data = file.read(section_nt.size)

        while previous_next != section_nt.next_offset:
            file.seek(section_nt.next_offset)
            section_offset = file.tell()
            previous_next = section_nt.next_offset
            data = file.read(Ewf.S_SECTION.size)
            section_nt = Ewf.NT_SECTION(*Ewf.S_SECTION.unpack_from(data, 0))
            if self.verbose > 0:
                print(
                    "0x%08x: type:%8s next:%x size:%x"
                    % (
                        section_offset,
                        section_nt.stype,
                        section_nt.next_offset,
                        section_nt.size,
                    )
                )
            if self.checksums:
                computed_sum = adler32(data[:-4])
                if section_nt.checksum != computed_sum:
                    print(
                        "checksum file:%08x != computed:%08x"
                        % (section_nt.checksum, computed_sum)
                    )

            self.parse_part(section_nt, file)

        self.chunks[header_nt.segment_num] = array.array(
            "L", sorted(self.chunks[header_nt.segment_num])
        )  # convert the set in array
        self.total_chunk_count += len(self.chunks[header_nt.segment_num])

    def display_properties(self):
        print(
            "chunk_count:0x%x, sectors_per_chunk:0x%x, bytes_per_sector:0x%x, sector_count:0x%x"
            % (
                self.chunk_count,
                self.sectors_per_chunk,
                self.bytes_per_sector,
                self.sector_count,
            )
        )
        # print('last_segment: %d' % self.last_segment)
        if "sha1" in self.hashes:
            print("sha1: %s" % (hexlify(self.hashes["sha1"])))
        print("md5: %s" % (hexlify(self.hashes["md5"])))
        if self.verbose > 0:
            for segment in range(1, self.last_segment + 1):
                print("segment #%d, filename: %s" % (segment, self.filename[segment]))
                print(
                    "  chunks count: %d (including uncompressed:%d, %.2f%%)"
                    % (
                        len(self.chunks[segment]),
                        len(self.uncompressed[segment]),
                        len(self.uncompressed[segment])
                        * 100
                        / len(self.chunks[segment]),
                    )
                )
                print(
                    "  data offsets: first:0x%x last:0x%x"
                    % (self.chunks[segment][0], self.chunks[segment][-1])
                )
                print("  absolute chunk number ranges", self.chunk_range[segment])
                print("  end_of_sectors: 0x%x" % self.end_of_sectors[segment])

    def compute_offset(self, offset):  # offset in bytes, multiple of 512
        if offset > self.sector_count * self.bytes_per_sector or offset < 0:
            raise ValueError("Offset out of bounds")
            return

        num_chunk = offset // self.chunk_size
        # print('num_chunk %d' % num_chunk)
        if num_chunk >= self.total_chunk_count:
            print("error num_chunk >= self.chunk_count")
            return

        # locate the segment
        segment = 1
        while (
            self.chunk_range[segment][0] > num_chunk
            or num_chunk > self.chunk_range[segment][1]
            and segment < self.last_segment
        ):
            segment += 1
        # locate the chunk
        chunk_num_in_segment = (
            num_chunk - self.chunk_range[segment][0]
        )  # relative chunk number (in segment), instead of absolute (in dump)
        return (
            segment,
            chunk_num_in_segment,
            offset % self.chunk_size,
        )  # return segment, index in self.chunks[ segment ] and ptr in chunk

    def seek(self, offset):
        segment, num_chunk_in_segment, ptr_in_chunk = self.compute_offset(offset)
        if (
            self.current_chunk_num != num_chunk_in_segment
            or self.current_segment != segment
        ):  # read new chunk if needed
            self.current_chunk_data = self.read_chunk(segment, num_chunk_in_segment)
            self.current_chunk_num = num_chunk_in_segment
            self.current_segment = segment
        self.ptr_in_current_chunk = ptr_in_chunk

    # allow to iterate chunk number inside segment and over different segments
    def next_chunk_num(self, segment, relative_chunk_num):
        if relative_chunk_num + 1 < len(
            self.chunks[segment]
        ):  # not the last chunk of the segment
            return segment, relative_chunk_num + 1
        else:
            if segment + 1 <= self.last_segment:  # must go to next segment
                return segment + 1, 0
            else:
                print(
                    "next_chunk_num error: segment %d, relative_chunk_num %d"
                    % (segment, relative_chunk_num)
                )

    def tell(self):
        chunks = 0
        for seg in range(1, self.current_segment):
            chunks += len(self.chunks[seg])  # count chunks in segment < current_segment
        chunks += self.current_chunk_num  # chunks from start of current segment
        offset = chunks * self.chunk_size + self.ptr_in_current_chunk
        return offset

    def get_offset(self):
        return self.tell()

    def read(self, size):  # emulate read() in a file system
        data = b""
        # print('%d %d' % (self.current_segment, self.current_chunk_num))
        if self.current_chunk_data is None:  # no chunk in cache yet
            self.current_chunk_data = self.read_chunk(
                self.current_segment, self.current_chunk_num
            )
            self.ptr_in_current_chunk = 0
        while size > 0:
            if (
                self.chunk_size - self.ptr_in_current_chunk >= size
            ):  # last read in current chunk
                data += self.current_chunk_data[
                    self.ptr_in_current_chunk : self.ptr_in_current_chunk + size
                ]
                self.ptr_in_current_chunk = self.ptr_in_current_chunk + size
                size = 0
            else:  # will need to read another chunk
                data += self.current_chunk_data[
                    self.ptr_in_current_chunk :
                ]  # read end of current chunk
                size -= self.chunk_size - self.ptr_in_current_chunk
                self.ptr_in_current_chunk = self.chunk_size
                if self.current_segment < self.last_segment or (
                    self.current_segment == self.last_segment
                    and self.current_chunk_num + 1
                    < len(self.chunks[self.current_segment])
                ):  # next chunk does exist
                    self.current_segment, self.current_chunk_num = self.next_chunk_num(
                        self.current_segment, self.current_chunk_num
                    )
                    self.current_chunk_data = self.read_chunk(
                        self.current_segment, self.current_chunk_num
                    )  # read next chunk
                    self.ptr_in_current_chunk = 0
                else:
                    # print('short read: self.current_segment %d, self.current_chunk_num %d' % (self.current_segment, self.current_chunk_num) )
                    return data
        return data

    def read_buffer_at_offset(self, nb_bytes: int, offset: int):
        self.seek(offset)
        return self.read(nb_bytes)

    def read_chunk(self, segment, chunk):  # number of chunk in segment
        # print('segment %d, chunk %d' % (segment, chunk))
        if chunk >= len(self.chunks[segment]) or chunk < 0:
            print("read_chunk: chunk number. segment %d chunk %d" % (segment, chunk))
            raise IndexError
        start_offset = self.chunks[segment][chunk]

        # seek
        self.filedesc[segment].seek(start_offset)  # seek in file segment

        # read
        if start_offset in self.uncompressed[segment]:
            data = self.filedesc[segment].read(self.chunk_size)  # without adler32
        else:
            if start_offset == self.chunks[segment][-1]:  # last chunk in segment
                end_offset = self.end_of_sectors[segment]
            else:
                end_offset = self.chunks[segment][chunk + 1]
            # print('start_offset %x end_offset %x ' % (start_offset, end_offset ) )
            compressed = self.filedesc[segment].read(
                end_offset - start_offset
            )  # compressed data includes adler32
            data = decompress(compressed)
        """if segment==3 and chunk==5026:
      printHex(data)"""
        return data

    def compute_image_hash(self, md):  # accessing chunk directly
        for segment in range(1, self.last_segment + 1):
            for chunk in range(len(self.chunks[segment])):
                data = self.read_chunk(segment, chunk)
                md.update(data)
        return md.digest()
