from distutils.core import setup, Extension

module = Extension('fparser',
                   sources = ['../common.cc', '../flows.cc', '../packer.cc', '../parser.cc', '../periodic_runner.cc', '../flowparser.cc', 'python_shim.cc'],
                   libraries = ['pcap', 'pthread'],
                   extra_compile_args = ['-I/Library/Developer/CommandLineTools/usr/bin/../include/c++/v1', 
                                         '-Wno-c++11-compat-deprecated-writable-strings',  '-g', '-pthread', 
                                         '-std=c++11', '-pedantic-errors', '-Winit-self', '-Wno-old-style-cast',
                                         '-Woverloaded-virtual', '-Wuninitialized', '-Wextra', '-O2', '-Wno-strict-prototypes',
                                         '-Wno-missing-field-initializers', '-Wno-write-strings'])

setup (name = 'FlowParser',
       version = '0.2.0',
       description = 'A flow parsing/dumping utility',
       ext_modules = [module],
       url = 'flowparser.googlecode.com',
       author = 'Nikola Gvozdiev',
       author_email = 'nikgvozdiev at gmail.com',
       license='MIT license',
       long_description=open('README').read())
