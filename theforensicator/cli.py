"""Console script for theforensicator."""

import fire

from .app import EWFImage


def cmd(ewf_file: str, out_dir: str = None, dump_dir: str = None, resolve_mft_file: str = None):
    """Parses a EWF file and dump interesting files found in the windows file
    system

    Args:
        ewf_file: File that will be analysed (*.E01)
        out_dir: Output directory where the *not resolved* MFT is written
        dump_dir: Directory where the MFT has already been dumped previously
        resolve_mft_file: Output file of MFT files / directories in JSON format
    """
    with EWFImage(ewf_file) as ewf:
        ewf.read_ewf()
        ewf.analyze_ntfs(out_dir=out_dir, dump_dir=dump_dir, resolve_mft_file=resolve_mft_file)


def main():
    fire.Fire(cmd)


if __name__ == "__main__":
    main()  # pragma: no cover
