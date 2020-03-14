pgp-milter
**********

Mail filter to automatically PGP encrypt messages


Install
=======

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
