#!/usr/bin/env python

from setuptools import setup

setup(name='OpenKart',
      version='0.1.0',
      description='Open-source SDK to manage and operate the kart RC toys '
                  'made and sold by a well-known Japanese video game company.',

      license='BSD',

      author='OpenKart SDK Developers',
      url='https://github.com/openkart-sdk',
      packages=['openkartd', 'openkartd.api'],

      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: BSD License',
          'Operating System :: POSIX :: Linux',
          'Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator',
      ],

      install_requires = [
          'cryptography',
          'aiohttp',
      ],

      entry_points={
          'console_scripts': [
              'openkartd = openkartd.__main__:main',
          ],
      },
     )
