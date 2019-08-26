from setuptools import setup

setup(
    name='virt_media_tool',
    version='0.1',
    py_modules=['virt_media_tool'],
    install_requires=['Click', 'hexdump', 'pycryptodomex'],
    entry_points='''
        [console_scripts]
        virt_media_tool=virt_media_tool:cli
    ''',
)