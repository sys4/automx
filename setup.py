#!/usr/bin/env python

from distutils.core import setup

setup(name='automx',
      description='Provides account configuration data to mailclients',
      url='http://automx.org/',
      download_url='https://github.com/sys4/automx/archive/automx-0.9.1.tar.gz',
      license='GPL',
      version='0.9',
      py_modules=['automx_wsgi'],
      packages=['automx'],
      package_dir={'': 'src'},
      data_files=[('/etc', ['src/conf/automx.conf'])],
      )

