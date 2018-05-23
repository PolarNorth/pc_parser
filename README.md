# pc_parser
Parser for .pc Phantom language class files
# Installation
Download or clone repository and install python 3.6 environment
# Usage
    parse_pc.py [-h] [-d] [-t] [-m] I F O

    positional arguments:
    I           Directory containing .pc files
    F           .pc file to parse
    O           Directory for program output

    optional arguments:

    -h, --help  show this help message and exit
    -d          Show debug information
    -t          Save information in .txt files
    -m          Show method information

One .txt file for each class and one .txt file for each method will be created together with .json containing all information from them.