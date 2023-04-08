"""Console script for theforensicator."""

import fire

from .app import EWFImage

def help():
    print("theforensicator")
    print("=" * len("theforensicator"))
    print("School project for forensic investigations")


def test():
    with EWFImage("../../Forensics/disk.E01") as ewf:
        ewf.read_ewf()
        ewf.analyze_ntfs()


def main():
    fire.Fire({"help": help, "test": test})


if __name__ == "__main__":
    main()  # pragma: no cover
