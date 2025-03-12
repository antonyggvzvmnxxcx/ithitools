# APNIC test.
#
# Load a et of parsed APNIC traces and create graphs
# 
# Usage: python rsv_second_pass.py <output_dir> <csv_file> ... <csv_file>

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

def usage():
    print("Usage: python rsv_second_pass.py <image_dir> <output_dir> <csv_file> ... <csv_file>\n")
    print("This script will load the csv files,")
    print("and write plot and histogram images in the specied image directory.")
    print("If willretains all ASes with more than 1000 UIDs.")

# Main program
if __name__ == "__main__":
    time_start = time.time()
    if len(sys.argv) < 3:
        usage()
        exit(-1)

    output_dir = sys.argv[1]
    csv_files = sys.argv[2:]

    # Load files that have been parsed in the first pass
    #
    ppq = rsv_log_parse.pivoted_per_query()
    nb_events = 0
    for csv_file in csv_files:
        nb_events_in_file = ppq.load_csv_log(csv_file)
        print("Read " + str(nb_events_in_file) + " from " + csv_file + " at " + str(time.time() - time_start) + " seconds.")
        nb_events += nb_events_in_file

    print("Loaded " + str(len(ppq.cc_AS_list)) + " CC+AS with " + str(nb_events) + " events at " + str(time.time() - time_start) + " seconds.")

    # Based on the number of event, we set a threshold on the number of "both" events
    # required to start the delay analysis and the graphs. The tests in practice recognizes
    # if we are running with a test file, and lowers the threshold so that we can
    # exercise the code, event if there are few points per graph.
    target_threshold = 1000
    if nb_events < 100000:
        target_threshold = 30

    # Once all events have been loaded, we compute for each UID the delay between the
    # arrival of the first event for that UID and the arrival of the first event in
    # each of the categories of resolvers.
    ppq.compute_delta_t()
    time_delays_computed = time.time()
    print("Delays computed at " + str(time_delays_computed - time_start) + " seconds.")

    # We prepare the graphs for all qualifying ASes
    key_list = ppq.key_list()
        
    # get the summaries per cc + AS
    summary_df = ppq.get_summaries(key_list, False);
    summary_file = os.path.join(output_dir, "summary.csv" )
    summary_df.to_csv(summary_file, sep=",")
    print("Published summaries for " + str(len(key_list)) + " CC+AS" + " in " + summary_file)
    time_summaries_computed = time.time()
    print("Summaries computed at " + str(time_summaries_computed - time_start) + " seconds.")

    # get the subnets used for each AS
    subnet_df = ppq.get_subnets()
    subnet_file = os.path.join(output_dir, "subnets.csv" )
    subnet_df.to_csv(subnet_file, sep=",")
    print("Published summaries for " + str(subnet_df.shape[0]) + " subnets" + " in " + subnet_file)
    time_summaries_published = time.time()
    print("Summaries published at " + str(time_summaries_published - time_start) + " seconds.")

    # Analyse the spread of delays for the AS that have a sufficient share of UID with events
    # from both ISP resolvers and public resolvers. 
    nb_published = 0
    for key in key_list:
        if ppq.cc_AS_list[key].nb_both + ppq.cc_AS_list[key].nb_others > target_threshold:
            # collect table, one row per event
            dot_df = ppq.get_delta_t_both(key)
            plot_delay_file = os.path.join(output_dir, key[:2] + "_" + key[2:] + "_plot_delays" )
            rsv_log_parse.do_graph(key, dot_df, plot_delay_file, x_delay=True, log_y=True)
            host_delay_files = os.path.join(output_dir,  key[:2] + "_" + key[2:] + "_hist_delays" )
            rsv_log_parse.do_hist(key, dot_df, image_file=host_delay_files)
            nb_published += 1
            if (nb_published%100) == 0:
                print("Published " + str(nb_published) + " AS graphs")
    print("Done publishing " + str(nb_published) + " AS graphs")
    time_finished = time.time()
    print("Finished at " + str(time_finished - time_start) + " seconds.")

    exit(0)


