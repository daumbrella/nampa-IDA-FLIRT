#!/usr/bin/env python

from builtins import range
import os
import sys

import nampa




def format_functions(ff):
    out = []
    for f in ff:
        out.append('{}{}:{}'.format('(l)' if f.is_local else '', f.offset, f.name))
    return ' '.join(out)


def format_tail_bytes(bb):
    out = []
    for b in bb:
        out.append('({:04X}: {:02X})'.format(b.offset, b.value))
    return ' '.join(out)


def format_refs(rr):
    out = []
    for r in rr:
        out.append('(REF {:04X}: {})'.format(r.offset, r.name))
    return 'XXX'.join(out)


def print_modules(node, level):
    for i, m in enumerate(node.modules):
        print("  "*level+" "+hex(m.crc_length)+" "+hex(m.crc16)+" "+hex(m.length)+" "+print_functions(m.public_functions))

def print_functions(functions):
    function_names=list()
    for function in functions:
        function_names.append(function.name)
    return str(function_names)
def recurse(node, level):
    print("  "*level, node.pattern)
    if node.is_leaf:
        print_modules(node, level + 1)
    else:
        for child in node.children:
            recurse(child, level + 1)

def recurse_err(node,level):
    print "  "*level+node.pattern
    if node.is_leaf:
       print_modules(node, level + 1)
    else:
        for child in node.children:
            recurse_err(child,level+1)

def main(fpath):
    sig = nampa.parse_flirt_pat_file(open(fpath,'r'))
    #for child in sig.root.children:
        #recurse_err(child, level=0)
    buf='23025001F991B5F82B02780BF5F3FB952000D001461646071D8CD0FB2D00BDF8'
    print(nampa.match_function(sig,buf))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} input_file.sig".format(sys.argv[0]))
        exit()

    main(sys.argv[1])
