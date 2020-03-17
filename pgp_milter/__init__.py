# make this a package.
import Milter


__version__ = "0.1.dev0"  # set also in setup.py


class GPGMilter(Milter.Base):
    """A milter that currently does nothing.
    """

    def __init__(self):
        self._id = Milter.uniqueID()
