"""Console script for theforensicator."""

import fire

from .app import EWFImage


def cmd(ewf_file: str, out_dir: str = None, dump_dir: str = None):
    """Parses a EWF file and dump interesting files found in the windows file
    system

    Args:
        ewf_file: File that will be analysed (*.E01)
        out_dir: Output directory where the *not resolved* MFT is written
        dump_dir: Directory where the MFT has already been dumped previously
    """
    with EWFImage(ewf_file) as ewf:
        ewf.read_ewf()
        ewf.analyze_ntfs(out_dir=out_dir, dump_dir=dump_dir)


def main():
    fire.Fire(cmd)


if __name__ == "__main__":
    main()  # pragma: no cover
