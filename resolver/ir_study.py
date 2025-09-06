# Study of how APNIC logs can inform us of behavior of iranian networks and
# network users in the month of June, 2025, i.e., before and
# after airborne attacks by Israel. The attacks started on 13 June 2025
# at 3:00 am (GMT+3), and continued until a cease fire on June 23. We
# have received data from APNIC covering traffic out of Iran from
# June 1, 2025 to June 20, 2025.
#
# The first step is to produce a sumamry listing of the traffic for
# each of these days.
#

from genericpath import isfile
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
    print("Usage: " + sys.argv[0] + " monthly_dir result_dir")

def get_totals_by_day(big_df):
    target = [ 'day', 'uids', 'q_uid_tags', 'q_repeats', 'isp', 'public', 'both', 'others', \
             'Same_AS', 'Same_group',  'Cloud', 'Same_CC', 'Other_cc', 'googlepdns', 'cloudflare', \
            'opendns', 'quad9', 'level3', 'neustar', 'he' ]
    days = big_df['day'].unique()
    t = []
    for day in days:
        day_df = big_df[ big_df['day'] == day ]
        r = []
        r.append(day)
        for col in target[1:]:
            r.append(day_df[col].sum())
        t.append(r)
    total_df = pd.DataFrame(t, columns = target)
    return total_df

def parse_resolver_in_file(day, file_name, ip2a4, ip2a6, as_names):
    exp_set = set ([ "0du" ])
    rr_set = set ([ "A", "AAAA", "HTTPS" ])
    open_set = set(['googlepdns', 'cloudflare', \
            'opendns', 'quad9', 'level3', 'neustar', 'he' ])
    r_dict = dict()
    for line in open(file_name, "r"):
        parsed = True
        try:
            x = rsv_log_parse.rsv_log_line()
            parsed = x.parse_line(line)
        except Exception as exc:
            traceback.print_exc()
            print('\nCode generated an exception: %s' % (exc))
            print("Cannot parse:\n" + line + "\n")
            parsed = False
        if parsed and x.query_experiment in exp_set and x.rr_type in rr_set:
            x.set_resolver_AS(ip2a4, ip2a6, as_names)
            if x.resolver_tag in open_set:
                logged_AS = x.resolver_tag
            else:
                logged_AS = x.resolver_AS
            key = day + '-' + logged_AS + '-' + x.query_AS
            if not key in r_dict:
                r_dict[key] = set()
            if not x.query_user_id in r_dict[key]:
                r_dict[key].add(x.query_user_id)
    t = []
    key_list = list(r_dict.keys())
    key_list.sort()
    for key in key_list:
        p = key.split("-")
        r = [ p[0], p[1], p[2], len(r_dict[key]) ]
        t.append(r)
    as_df = pd.DataFrame(t, columns = [ 'day', 'resolver_AS', 'query_AS', 'hits' ])
    return as_df

def get_as_total_df(big_as_df):
    days =  big_as_df['day'].unique()
    resolvers = big_as_df['resolver_AS'].unique()

    days.sort()
    resolvers.sort()
    t = []
    for day in days:
        day_as_df = big_as_df[ big_as_df['day'] == day ]
        for res in resolvers:
            day_res_df = day_as_df [ day_as_df['resolver_AS'] == res]
            if day_res_df.shape[0] != 0:
                r = [ day, res, day_res_df['hits'].sum() ]
                t.append(r)
    as_total_df = pd.DataFrame(t, columns=['days', 'resolver_AS', 'hits' ])
    return as_total_df

def get_as_days(big_as_df):
    days =  big_as_df['day'].unique()
    resolvers = big_as_df['resolver_AS'].unique()
    days.sort()
    resolvers.sort()
    columns = [ 'resolver_AS' ]
    others = [ 'others' ]
    for day in days:
        columns.append(day)
        others.append(0)
    columns.append('total')
    others.append(0)
    columns.append('t16-20')
    others.append(0)
    t = []
    for res in resolvers:
        res_df = big_as_df[ big_as_df['resolver_AS'] == res ]
        r = [ res ]
        r_tot = 0
        r_t16_20 = 0
        for day in days:
            day_res_df = res_df [ res_df['day'] == day]
            dt = day_res_df['hits'].sum()
            r.append(dt)
            r_tot += dt
            if day >= 16:
                r_t16_20 += dt
        if r_tot > 5000 or r_t16_20 > 200:
            r.append(r_tot)
            r.append(r_t16_20)
            t.append(r)
        else:
            for i in range(0, len(days)):
                others[i+1] += r[i+1]
            others[len(days)+1] += r_tot
            others[len(days)+2] += r_t16_20
    t.append(others)
    as_days_df = pd.DataFrame(t, columns=columns)
    return as_days_df


def load_tables():
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
    return ip2a4, ip2a6, as_names

# Main program
if __name__ == "__main__":
    time_start = time.time()
    if len(sys.argv) != 3:
        usage()
        exit(-1)

    ir_src = sys.argv[1]
    ir_res = sys.argv[2]

    
    summary_file = os.path.join(ir_res, "summary.csv")
    as_summary_file = os.path.join(ir_res, "as_summary.csv")
    time_loaded = time_start

    if not os.path.isfile(summary_file) or not os.path.isfile(as_summary_file):
        ip2a4, ip2a6, as_names = load_tables()
        time_loaded = time.time()
        print("Tables loaded at " + str(time_loaded - time_start) + " seconds.")


    if os.path.isfile(summary_file):
        big_df = pd.read_csv(summary_file)
    else:
        days = os.listdir(sys.argv[1])
        summary_df_list = []

        time_old_file = time_loaded
        for day in days:
            day_src = os.path.join(ir_src, day)
            day_dns_log = os.path.join(day_src, "queries.log")
            if not os.path.isfile(day_dns_log):
                print("Not a file: " + day_dns_log)
            else:
                ppq = rsv_log_parse.pivoted_per_query()
                nb_events_in_file = ppq.quicker_load(day_dns_log, ip2a4, ip2a6, as_names, rr_types=['A', 'AAAA', 'HTTPS'],
                                                    experiment=['0du'], query_ASes=[], time_start=time_old_file)
                time_last_file = time.time()
                print("Read " + str(nb_events_in_file) + " from " + day_dns_log + " at " + str(time_last_file - time_old_file) + " seconds.")
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
                # Declare a list that is to be converted into a column
                df_days = []
                for x in range(0, summary_df.shape[0]):
                    df_days.append(day)
                summary_df['day'] = df_days
                summary_df_list.append(summary_df)
                print("After " + day + ", " + str(len(summary_df_list)) + " in summary list.")
                summary_day_file = os.path.join(ir_res, "summary-" + day + ".csv")
                summary_df.to_csv(summary_day_file)
                time_summaries_computed = time.time()
                print("Summaries for day: " + day + " computed at " + str(time_summaries_computed - time_start) + " seconds.")
                time_old_file = time_summaries_computed

        for i in range(0, len(summary_df_list)):
            print(str(i) + " df: " + str(summary_df_list[i].shape[0]))
        big_df = pd.concat(summary_df_list)
        print("big: " + str(big_df.shape[0]))
        big_df.to_csv(summary_file)
        print("Saved " + str(big_df.shape[0]) + " events at " + str(time.time() - time_start) + " seconds.")

    # Compute a summary per day
    total_file = os.path.join(ir_res, "total_by_days.csv")
    if not os.path.isfile(total_file):
        total_df = get_totals_by_day(big_df)
        total_df.to_csv(total_file)
    
    if os.path.isfile(as_summary_file):
        big_as_df = pd.read_csv(as_summary_file)
    else:
        days = os.listdir(sys.argv[1])
        as_df_list = []
        for day in days:
            day_src = os.path.join(ir_src, day)
            day_dns_log = os.path.join(day_src, "queries.log")
            as_day_df = parse_resolver_in_file(day, day_dns_log, ip2a4, ip2a6, as_names)
            as_df_list.append(as_day_df)
            print("Found " + str(as_day_df.shape[0]) + " AS keys in " +  day_dns_log)
        big_as_df = pd.concat(as_df_list)
        print("big as: " + str(big_as_df.shape[0]))
        big_as_df.to_csv(as_summary_file)
        print("Saved " + str(big_as_df.shape[0]) + " events in " + as_summary_file + " at " + str(time.time() - time_start) + " seconds.")

    as_total_file = os.path.join(ir_res, "as_total_by_days.csv")
    if not os.path.isfile(as_total_file):
        as_total_df = get_as_total_df(big_as_df)
        as_total_df.to_csv(as_total_file)
        print("Saved " + str(as_total_df.shape[0]) + " events in " + as_total_file + " at " + str(time.time() - time_start) + " seconds.")

    as_days_file = os.path.join(ir_res, "as_days.csv")
    if not os.path.isfile(as_days_file):
        as_days_df = get_as_days(big_as_df)
        as_days_df.to_csv(as_days_file)
        print("Saved " + str(as_days_df.shape[0]) + " events in " + as_days_file + " at " + str(time.time() - time_start) + " seconds.")

    exit(0)
