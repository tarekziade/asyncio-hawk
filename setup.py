import sys
from setuptools import setup, find_packages


install_requires = []
description = ''

classifiers = ["Programming Language :: Python",
               "License :: OSI Approved :: Apache Software License",
               "Development Status :: 5 - Production/Stable",
               "Programming Language :: Python :: 3 :: Only",
               "Programming Language :: Python :: 3.5",
               "Programming Language :: Python :: 3.6"]


setup(name='asynchawk',
      version='0.1',
      url='',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      classifiers=classifiers,
      install_requires=install_requires,
      )
