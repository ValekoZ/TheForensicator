# Usage


## CLI

To use TheForensicator as a command:

> **NAME**
>
> &nbsp;&nbsp;&nbsp;&nbsp;theforensicator - Parses a EWF file and dump interesting files found in the windows file system
>
>
> **SYNOPSIS**
>
> &nbsp;&nbsp;&nbsp;&nbsp;theforensicator *EWF_FILE* <flags>
>
>
> **DESCRIPTION**
>
> &nbsp;&nbsp;&nbsp;&nbsp;Parses a EWF file and dump interesting files found in the windows file system
>
>
> **POSITIONAL ARGUMENTS**
>
> &nbsp;&nbsp;&nbsp;&nbsp;**EWF_FILE**
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Type: str
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;File that will be analysed (\*.E01)
>
>
> **FLAGS**
>
> &nbsp;&nbsp;&nbsp;&nbsp;--out\_dir=*OUT_DIR*
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Type: Optional[str]
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Default: None
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Output directory where the *not resolved* MFT is written
>
> &nbsp;&nbsp;&nbsp;&nbsp;--dump\_dir=*DUMP_DIR*
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Type: Optional[str]
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Default: None
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Directory where the MFT has already been dumped previously
>
> &nbsp;&nbsp;&nbsp;&nbsp;--resolve\_mft\_file=*RESOLVE_MFT_FILE*
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Type: Optional[str]
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Default: None
>
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Output file of MFT files / directories in JSON format
>
>
> **NOTES**
>
> &nbsp;&nbsp;&nbsp;&nbsp;You can also use flags syntax for POSITIONAL ARGUMENTS
>


## As a module

First, you need to import the module.

```
    import theforensicator
```


Then, you can use the different classes and methods from the package (see more
[on the documentation](../api/))
