# PsAll

This Volatility3 plugin extends the default Linux PsList plugin with information about the environment variables.


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

## License
https://www.volatilityfoundation.org/license/vsl-v1.0

## Authors
Rick Knegt & Bart Steur (https://os3.nl students)