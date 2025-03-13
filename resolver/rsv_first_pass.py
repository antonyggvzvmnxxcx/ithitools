# APNIC test.
#
# Load an APNIC trace and store the filtered and parsed version in a csv file
# 
# Usage: python rsv_as_study.py <csv_file> <log_file> <ASxxxx> <source_directory>

import sys
import os
from pathlib import Path
import ip2as
import rsv_log_parse
#import rsv_both_graphs
import pandas as pd
import traceback
import top_as
import time
import bz2

def usage():
    print("Usage: python rsv_first_pass.py <csv_file> <log_file> <ASxxxx>\n")
    print("This script will parse the log file, extract data for the specified ASes,")
    print("and save the parsed data in the csv file.")
    print("If no AS is specified, retains all ASes with more than 1000 UIDs.")

def get_log_as_df(log_file, ip2a4, ip2a6, as_table, rr_types=[], experiment=[], query_ASes=[], log_threshold = 15625, time_start=0):
        nb_events = 0
        lth = log_threshold;
        
        filtering = len(rr_types) > 0 or len(experiment) > 0 or len(query_ASes) > 0
        q_set = set(query_ASes)
        t = []
        old_time = 0
        if log_file.endswith(".bz2"):
            F = bz2.open(log_file, "rt")
        else:
            F = open(log_file, "r")
        for line in F:
            parsed = True
            try:
                x = rsv_log_parse.rsv_log_line()
                parsed = x.parse_line(line)
            except Exception as exc:
                traceback.print_exc()
                print('\nCode generated an exception: %s' % (exc))
                print("Cannot parse:\n" + line + "\n")
                parsed = False
            if parsed:
                if (not filtering) or x.filter(rr_types=rr_types, experiment=experiment, query_ASes=q_set):
                    x.set_resolver_AS(ip2a4, ip2a6, as_table)
                    t.append(x.row())
                    nb_events += 1

                    if (nb_events%lth) == 0:
                        new_time = time.time() - time_start
                        if time_start > 0:
                            print("loaded " + str(nb_events) + " events at " + str(new_time))
                        else:
                            print("loaded " + str(nb_events) + " events.")
                        if lth < 1000000:
                            lth *= 2
        df = pd.DataFrame(t, columns= rsv_log_parse.rsv_log_line.header())
        return df

# Main program
if __name__ == "__main__":
    time_start = time.time()
    if len(sys.argv) < 3:
        usage()
        exit(-1)

    csv_file = sys.argv[1]
    log_file = sys.argv[2]
    target_ASes = []
    if len(sys.argv) > 3:
        target_ASes = sys.argv[3:]
        if len(target_ASes) == 1 and target_ASes[0] == "TopAS":
            target_ASes = top_as.top_as_list()
    
    source_path = Path(__file__).resolve()
    resolver_dir = source_path.parent
    auto_source_dir = resolver_dir.parent
    print("Auto source path is: " + str(auto_source_dir) + " (source: " + str(source_path) + ")")
    source_dir = os.path.join(auto_source_dir, "data") 
    ip2a4_file = os.path.join(source_dir, "ip2as.csv") 
    ip2a6_file = os.path.join(source_dir, "ip2asv6.csv")
    as_names_file = os.path.join(source_dir, "as_names.csv")      
    ip2a4 = ip2as.ip2as_table()
    ip2a4.load(ip2a4_file)
    ip2a6 = ip2as.ip2as_table()
    ip2a6.load(ip2a6_file)
    as_names = ip2as.asname()
    as_names.load(as_names_file)
    time_loaded = time.time()
    print("Tables loaded at " + str(time_loaded - time_start) + " seconds.")

    df = get_log_as_df(log_file, ip2a4, ip2a6, as_names, rr_types=['A', 'AAAA', 'HTTPS'], experiment=['0du'], query_ASes=target_ASes, log_threshold = 15625, time_start=time_start)
    time_file_read = time.time()
    print("File read at " + str(time.time() - time_start) + " seconds.")
    if df.shape[0] == 0:
        print("No event found. Are you sure this is a correct file?")
    else:
        df.to_csv(csv_file)
        print("Saved " + str(df.shape[0]) + " events to " + csv_file + " at " + str(time.time() - time_start) + " seconds.")

    exit(0)


