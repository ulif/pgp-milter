# make this a package.
import Milter


__version__ = "0.1.dev0"


class GPGMilter(Milter.Base):
    """A milter that currently does nothing.
    """
    pass
