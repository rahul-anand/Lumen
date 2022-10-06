from pathlib import Path

from setuptools import find_packages, setup

VERSION = "0.0.1"
DESCRIPTION = "lumen"
this_directory = Path(__file__).parent
LONG_DESCRIPTION = DESCRIPTION
# (this_directory / "README.md").read_text()

# Setting up
setup(
    # the name must match the folder name 'verysimplemodule'
    name="lumen",
    version=VERSION,
    author="Rahul Anand Sharma",
    author_email="rahulans@andrew.cmu.edu",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "torch",
        "torchvision",
        "memory_profiler",
        "flaml",
        "psutil",
        "scikit-learn",
        "pypacker",
        "matplotlib",
        "more_itertools",
        "xgboost_ray",
        "zat",
        "ray",
        "tensorflow",
        "tqdm",
        "azure-storage-blob",
        "adlfs",
        "pyarrow",
        "scapy",
        "modin[ray]",
        "ipython",
    ],  # add any additional packages that
    # needs to be installed along with your package. Eg: 'caer'
    # keywords=['python', 'netshare'],
    # classifiers=[
    #     "Development Status :: 3 - Alpha",
    #     "Intended Audience :: Education",
    #     "Programming Language :: Python :: 3.6",
    #     "Operating System :: MacOS :: MacOS X",
    #     "Operating System :: Microsoft :: Windows",
    # ]
)
