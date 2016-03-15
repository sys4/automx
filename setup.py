#!/usr/bin/env python

from distutils.core import setup

setup(name='automx',
      description='Provides account configuration data to mailclients',
      url='http://automx.org/',
      license='GPL',
      version='1.1.0',
      py_modules=['automx_wsgi'],
      packages=['automx'],
      package_dir={'': 'src'},
      data_files=[('/etc', ['src/conf/automx.conf'])],
      scripts=['src/automx-test'],
      requires=['future', 'lxml', 'ipaddr', 'pyldap', 'sqlalchemy']
      )
