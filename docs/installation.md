# Installation
## Stable release

To install TheForensicator, run this command in your
terminal:

``` console
pip install theforensicator
```

This is the preferred method to install TheForensicator, as it will always
install the most recent stable release.

If you don't have [pip][] installed, this [Python installation guide][]
can guide you through the process.


## Optionnal dependencies

`libewf-python` is an optionnal dependency as we have [a python implementation
of this library from Laurent CLÉVY](https://github.com/lclevy/miniEwf). Note
that if you expect to have good performances, you should probably install it.


## From source

The source for TheForensicator can be downloaded from
the [Github repo][].

You can either clone the public repository:

``` console
git clone git://github.com/ValekoZ/theforensicator
```

Or download the [tarball][]:

``` console
curl -OJL https://github.com/ValekoZ/theforensicator/tarball/master
```

Once you have a copy of the source, you can install it with:

``` console
pip install .
```

  [pip]: https://pip.pypa.io
  [Python installation guide]: http://docs.python-guide.org/en/latest/starting/installation/
  [Github repo]: https://github.com/%7B%7B%20cookiecutter.github_username%20%7D%7D/%7B%7B%20cookiecutter.project_slug%20%7D%7D
  [tarball]: https://github.com/%7B%7B%20cookiecutter.github_username%20%7D%7D/%7B%7B%20cookiecutter.project_slug%20%7D%7D/tarball/master
