# Verify that the summary numbers are consistent with the definition.
#
# We need to see:
#
# uids == q_total
# isp+public+both+others == q_total
# isp <= Same_AS + Same_group
# others <= 'Cloud', 'Same_CC', 'Other_cc'
# public <= sum [ 'googlepdns', 'cloudflare', 'opendns', 'quad9', 'level3', 'neustar', 'he' ]

import sys
import pandas as pd

total_check = [ 'uids' ]
total_list = [ 'isp', 'public', 'both', 'others' ]
isp_list = [ 'Same_AS', 'Same_group' ]
others_list = [ 'Cloud', 'Same_CC', 'Other_cc' ]
public_list = [  'googlepdns', 'cloudflare', 'opendns', 'quad9', 'level3', 'neustar', 'he' ]

all_ok = True

def usage():
    print("Usage: python rsv_summary_check.py summary.csv")

def one_check(x, key, check_list, is_exact):
    total = 0
    for tag in check_list:
        total += x[tag]
    if is_exact:
        is_ok = (x[key] == total)
    else:
        is_ok = (x[key] <= total)
    if not is_ok:
        s = "Fail check for " + x['q_cc'] + "/" + x['q_AS'] + ": " + key + "(" + str(x[key]) + ")" 
        if is_exact:
            s += " != \n"
        else:
            s += " > \n"
        for i in range(0, len(check_list)):
            if i != 0:
                s += " + "
            s += check_list[i] + "(" + str(x[check_list[i]]) + ")"
        print(s)
    return is_ok

def item_check(x):
    is_ok = \
        one_check(x, 'q_total', total_check, True) and \
        one_check(x, 'q_total', total_list, True) and \
        one_check(x, 'isp', isp_list, False) and \
        one_check(x, 'others', others_list, False) and \
        one_check(x, 'public', public_list, False)
    if not is_ok:
        all_ok = False


# main
if len(sys.argv) != 2:
    usage()
    exit -1
summary_csv = sys.argv[1]
df = pd.read_csv(summary_csv)
df.apply(lambda x: item_check(x), axis=1)

if all_ok:
    exit(0)
else:
    exit(-1)
