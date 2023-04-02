import pyreadpartitions as pypart

class NTFS(object):
    def __init__(self, ewf_image: "EWFImage", partition) -> None:
        self.handle     = ewf_image.handle
        self.verbosity  = ewf_image.verbosity
        self.partition  = partition
        self._start     = self.partition.first_lba

        if self.verbosity:
            print("[+] NTFS partition at sector %#x" % (self.partition.first_lba))
    
    def _extract_file(self):
        pass

    def _analyze_mft(self):
        print("[?] Analyzing MFT")
    
    def _analyze_registry(self):
        print("[?] Analyzing registries")

    def _analyze_winsec(self):
        print("[?] Analyzing Windows Security")