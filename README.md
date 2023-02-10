# PsAll

This Volatility 3 plugin extends the default Linux PsList plugin with information about the environment variables.


## Installation
First, download `psall.py` or clone this repo with:

```bash
git clone github.com/rknegt/psall
```
Then, copy `psall.py` to `plugins/` folder.

## Usage
```bash
python3 vol.py -f <memory_file> -p plugins psall
```

## Disclaimer
This plugin is only tested on memory dumps of an Ubuntu 20.04 VM, with kernel v5.8.0-25-generic. The kernel memory dumps were taken with `xl core-dump` because the VM was running on a Xen Project Hypervisor. Unfortunately, because Volatility 3 did not support Xen memory dumps when making this plugin, we only tested our setup on the "feature/xen-coredump-support" branch of Volatility 3.

## License
https://www.volatilityfoundation.org/license/vsl-v1.0

## Authors
Rick Knegt & Bart Steur (https://os3.nl students)