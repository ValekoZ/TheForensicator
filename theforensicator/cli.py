"""Console script for theforensicator."""

import fire
from .app import EWFImage
from os.path import dirname, normpath, isfile, exists

from pathlib import Path

import yaml
import glob

def cmd(ewf_file: str, dump_dir: str = None, resolve_mft_file: str = None, dmp_file: str = None, clear_cache: str = None, extract_artefacts: str = None):
    """Parses a EWF file and dump interesting files found in the windows file
    system

    Args:
        ewf_file: File that will be analysed (*.E01)
        dump_dir: Directory location to store dumped data (default location is current execution directory)
        resolve_mft_file: Output file where to store MFT files / directories in JSON format.
        dmp_file: Filename to dump from the disk (ex: "C:\\Windows\\System32\\cmd.exe")
        extract_artefacts: Extract automatically artefacts (Registry hives, ...) to dump_dir
    """
    with EWFImage(ewf_file) as ewf:
        ewf.read_ewf()

        if dmp_file:
            if type(dmp_file) is not str:
                print("[?] --dump-file is empty, you must enter a valid filename.")
                exit()

        ewf.analyze_ntfs(resolve_mft_file, clear_cache)
        
        if dmp_file:
            ewf.dump_file([dmp_file], dump_dir)

        if extract_artefacts:
            artefact_files = glob.glob(f"{dirname(__file__)}/artefacts/*.yaml")

            for artefact in artefact_files:
                with open(artefact, "r") as _artefact:
                    data = yaml.safe_load(_artefact.read())
                    
                    if data is None:
                        continue

                    if dump_dir and type(dump_dir) is str:
                        out_dir = normpath(f"{dump_dir}/{data['dirname']}")
                    else:
                        out_dir = normpath(f"./{data['dirname']}")

                    if not exists(out_dir):
                        Path(out_dir).mkdir(parents=True, exist_ok=True)

                    ewf.dump_file(data["files"], normpath(out_dir))
                    _artefact.close()

def main():
    fire.Fire(cmd)

if __name__ == "__main__":
    main()  # pragma: no cover
