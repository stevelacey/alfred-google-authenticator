Alfred Workflow: Google Authenticator
=====================================

[![CI](https://img.shields.io/github/actions/workflow/status/stevelacey/alfred-google-authenticator/ci.yml?branch=master&style=flat-square)](https://github.com/stevelacey/alfred-google-authenticator/actions/workflows/ci.yml?query=branch:master)
[![Coverage](https://img.shields.io/codecov/c/github/stevelacey/alfred-google-authenticator?style=flat-square)](https://codecov.io/gh/stevelacey/alfred-google-authenticator)
[![License](https://img.shields.io/github/license/stevelacey/alfred-google-authenticator?style=flat-square)](LICENSE.txt)

An Alfred workflow for Google Authenticator that generates TOTP and copies them to the clipboard.


Installation
------------

Create a `~/.config/google-authenticator` file with your secrets:

```ini
[Google]
secret=xxxxxxxxxxxxxxxxxx

[Evernote]
secret=yyyyyyyyyyyyyyyyyy
```

A `~/.gauth` file from the original workflow still works if there isn't one in `~/.config`.

[Download](https://github.com/stevelacey/alfred-google-authenticator/raw/master/Google%20Authenticator.alfredworkflow) and import to Alfred


Dependencies
------------

- Alfred with PowerPack
- Python3


Development
-----------

After modifying files locally, run `bundle.sh` to update the workflow file, and
commit the workflow file update to this repository.

Run the tests with `python3 -m unittest discover -s tests`.


Acknowledgment
--------------

- Forked from [Alfred Workflow: Google Authenticator](https://github.com/moul/alfred-workflow-gauth)
  - [Manfred Touron](https://github.com/moul)
  - Licensed under MIT
- Original source code
  - [Manfred Touron](https://github.com/moul)
- Serial contributor
  - [Gilberto Olimpio](https://github.com/golimpio)


License
-------

MIT
