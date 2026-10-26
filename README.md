Alfred Workflow: Google Authenticator
=====================================

An Alfred workflow for Google Authenticator that generates TOTP and copies them to the clipboard.


Installation
------------

Create a `~/.gauth` file with your secrets:

```ini
[Google]
secret=xxxxxxxxxxxxxxxxxx

[Evernote]
secret=yyyyyyyyyyyyyyyyyy
```

[Download](https://github.com/stevelacey/alfred-google-authenticator/raw/master/Google%20Authenticator.alfredworkflow) and import to Alfred


Dependencies
------------

- Alfred with PowerPack
- Python3


Development
-----------

After modifying files locally, run `bundle.sh` to update the workflow file, and
commit the workflow file update to this repository.


Acknowledgment
--------------

- Forked from [Alfred Workflow: Google Authenticator](https://github.com/moul/alfred-workflow-gauth)
  - [Manfred Touron](https://github.com/moul)
  - Licensed under MIT
- Original alarm clock icon
  - [Alex Auda Samora from The Noun Project](http://thenounproject.com/razerk/)
  - Licensed under Creative Commons Attribution
- Original source code
  - [Manfred Touron](https://github.com/moul)
- Serial contributor
  - [Gilberto Olimpio](https://github.com/golimpio)


License
-------

MIT
