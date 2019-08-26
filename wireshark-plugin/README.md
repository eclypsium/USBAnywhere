# Dependencies

* [lrc4](https://github.com/CheyiLin/lrc4)

# Installing

1. Locate your Wireshark plugin folder (see [Plugin folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) in the Wireshark manual)
1. Clone lrc4 into the plugins directory:

   `git clone https://github.com/CheyiLin/lrc4`
1. Copy usbanywhere.lua into the plugins directory

# Using

USBAnywhere should automatically be enabled for TCP port 623.

# Future work

* Decode USB packets in the payloads