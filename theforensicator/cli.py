"""Console script for theforensicator."""

import fire

from .app import EWFImage


def help():
    print("theforensicator")
    print("=" * len("theforensicator"))
    print("School project for forensic investigations")


def test():
    with EWFImage("/home/lucas/Downloads/Fofo/disk.E01") as ewf:
        ewf.read_ewf()
        ewf.analyze_ntfs(out_dir="../../", dump_dir="")

def main():
    fire.Fire({"help": help, "test": test})

if __name__ == "__main__":
    main()  # pragma: no cover
