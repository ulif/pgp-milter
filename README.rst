pgp-milter
**********

Mail filter to automatically PGP encrypt messages


Install
=======

Prerequisites
-------------

We need `pymilter` which relies on the `libmilter` C-library. So, we have to
install `libmilter` first.  On recent Debian/Ubuntu it is sufficient to do

    $ sudo apt install libmilter-dev

Install from Source
-------------------

mainly for development.

Clone the source::

    $ git clone https://github.com/ulif/pgp-milter
    $ cd php-milter

Create and activate a virtualenv::

    $ virtualenv venv
    $ source ./venv/bin/activate.sh

Then, from this directory, install the package::

    [venv] $ pip install -e .

Running Tests
=============

We use `tox` and `py-test` for testing. So,::

    $ pip install tox
    $ tox

should run all tests.
