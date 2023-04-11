# Usage


## CLI

To use TheForensicator as a command:

> **NAME**
>
>         theforensicator - Parses a EWF file and dump interesting files found in the windows file system
>
> **SYNOPSIS**
>
>         theforensicator *EWF_FILE* <flags>
>
> **DESCRIPTION**
>
>         Parses a EWF file and dump interesting files found in the windows file system
>
> **POSITIONAL ARGUMENTS**
>
>         **EWF_FILE**
>             Type: str
>             File that will be analysed (\*.E01)
>
> **FLAGS**
>
>         --out\_dir=*OUT_DIR*
>             Type: Optional[str]
>             Default: None
>             Output directory where the *not resolved* MFT is written
>         --dump\_dir=*DUMP_DIR*
>             Type: Optional[str]
>             Default: None
>             Directory where the MFT has already been dumped previously
>         --resolve\_mft\_file=*RESOLVE_MFT_FILE*
>             Type: Optional[str]
>             Default: None
>             Output file of MFT files / directories in JSON format
>
> **NOTES**
>
>         You can also use flags syntax for POSITIONAL ARGUMENTS


## As a module

First, you need to import the module.

```
    import theforensicator
```


Then, you can use the different classes and methods from the package (see more
[on the documentation](../api/))
