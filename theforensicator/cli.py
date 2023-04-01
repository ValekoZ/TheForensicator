"""Console script for theforensicator."""

import fire


def help():
    print("theforensicator")
    print("=" * len("theforensicator"))
    print("School project for forensic investigations")


def main():
    fire.Fire({"help": help})


if __name__ == "__main__":
    main()  # pragma: no cover
