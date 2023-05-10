# entitlements

Scan file system extracting entitlements from Mach-O binaries (and the raw code signature segment).
Can print findings to stdout or store them to an sqlite3 database.

A simple Python script built mostly by **GitHub Copilot** as an experiment.

There are a number of decisions - like the globals - that I would not have made, but I've left them in place.
The purpose was to use Copilot as much as possible.  Through better prodding on my part I could have gotten
Copilot to write cleaner code.

Developed using Python 3.11

For more details see the two posts:
- [Copilot Spaghetti](https://www.nubco.xyz/blog/copilot-spaghetti/index.html)
- [Entitlements](https://www.nubco.xyz/blog/entitlements/index.html)


## License

entitlements is released under the [MIT License](https://github.com/nubcoxyz/entitlements/blob/master/LICENSE) - Copyright (c) 2023 nubco, llc