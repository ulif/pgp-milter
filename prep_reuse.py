# Prepare sdist package for being scanned by FSFE reuse.
#
# Extract sdist package to local dir and remove packaging artefacts
#
import os
import tarfile

src_path = os.environ["TOX_PACKAGE"]
assert os.environ["TOX_WORK_DIR"] in os.getcwd()  # only run in tox envs
with tarfile.open(src_path) as tar:
    members = tar.getmembers()
    # remove packaging artefacts
    members = [m for m in members if not m.name.endswith("PKG-INFO")]
    members = [m for m in members if ".egg-info" not in m.name]
    tar.extractall(".", members)
os.rename(os.listdir()[0], "pgp-milter")
