import pyreadpartitions as pypart

import theforensicator


class GPT(object):
    def __init__(self, ewf_image: "theforensicator.app.EWFImage") -> None:
        self.handle = ewf_image.handle
        self.verbosity = ewf_image.verbosity
        self._read_gpt()

        if self.verbosity:
            self._print_gpt_info()

    def _read_gpt(self):
        self.gpt_header = pypart.read_gpt_header(self.handle, lba_size=512)
        self.gpt_partitions = pypart.read_gpt_partitions(
            self.handle, self.gpt_header, lba_size=512
        )

    def _print_gpt_info(self):
        print("GPT INFOS")
        for (i, partition) in enumerate(self.gpt_partitions):
            print("=" * 0x40)
            print("Partition %d" % i)
            for key in partition._asdict().keys():
                print("\t%-16s : %s" % (key, partition._asdict()[key]))
