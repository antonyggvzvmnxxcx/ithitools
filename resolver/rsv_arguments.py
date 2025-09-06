#
# Handling of arguments for statistics.
#
# Common arguments include list of selected AS and
# list of input files.

import sys
import os

def parse_AS_list(argv):
    ases = []
    for arg in argv:
        if not arg.startswith("AS"):
            break;
        ases.append(arg)
    return ases

def check_single_file(arg, endings):
    is_valid = (len(endings) == 0)
    for ending in endings:
        if arg.endswith(ending):
            is_valid = True
            break
    if is_valid:
        if not os.path.isfile(arg):
            is_valid = False
    return is_valid

def parse_file_pattern(arg, endings):
    print("pattern: " + arg)
    path_list = []
    prefix = os.path.basename(arg)
    fdir = os.path.dirname(arg)
    print("dir: " + fdir)
    print("prefix: " + prefix)

    if os.path.isdir(fdir):
        for name in os.listdir(fdir):
            if name.startswith(prefix):
                fpath = os.path.join(fdir, name)
                if check_single_file(fpath, endings):
                    path_list.append(fpath)
    return path_list
        

def parse_file_list(argv, endings):
    flist = []
    has_error = False

    for arg in argv:
        if arg.endswith('*'):
            # get all the files starting with that name
            path_list = parse_file_pattern(arg[:-1], endings)
            if len(path_list) == 0:
                print("No file matching: " + arg)
                has_error = True
            else:
                flist += path_list
        elif check_single_file(arg, endings):
            flist.append(arg)
        else:
            print("Not a valid file: " + arg)
            has_error = True
    return flist, has_error