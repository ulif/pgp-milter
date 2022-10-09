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
    def is_within_directory(directory, target):
        
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
    
        prefix = os.path.commonprefix([abs_directory, abs_target])
        
        return prefix == abs_directory
    
    def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
    
        for member in tar.getmembers():
            member_path = os.path.join(path, member.name)
            if not is_within_directory(path, member_path):
                raise Exception("Attempted Path Traversal in Tar File")
    
        tar.extractall(path, members, numeric_owner=numeric_owner) 
        
    
    safe_extract(tar, ".", members)
os.rename(os.listdir()[0], "pgp-milter")
