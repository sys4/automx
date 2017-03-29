#!/usr/bin/env python

from distutils.core import setup

setup(name='automx',
      description='Provides account configuration data to mailclients',
      url='https://github.com/sys4/automx',
      author_email='c@roessner.co',
      maintainer='Christian Roessner',
      keywords=['wsgi', 'autoconfig', 'autodiscover', 'mobileconfig'],
      license='GNU GPLv3',
      version='1.1.1',
      py_modules=['automx_wsgi'],
      packages=['automx'],
      package_dir={'': 'src'},
      data_files=[('/etc', ['src/conf/automx.conf'])],
      scripts=['src/automx-test'],
      requires=['future', 'lxml', 'ipaddress'],
      classifiers=[
            'Development Status :: 4 - Beta',
            'Environment :: No Input/Output (Daemon)',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'Intended Audience :: Telecommunications Industry',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Topic :: Communications :: Email',
            'Topic :: Utilities',
        ]
      )
