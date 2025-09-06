#
# HTTPS study
#
# Collect a list of transactions, checking whether they have an HTTPS query or not.
# 
# Extract time series, by slice, with number of transaction and number of HTTPS query,
# either for all traffic or for a specific AS. Slice is one hour for the
# global metric, 5 minute for the per AS extracts.
#
# Write the time slice result in CSV files, either global (https_metric) or
# per AS (https_ASnnnn.csv).
#
# Specific consideration: need to set up the start of the time slices.
# We get that from the minimum slice in the set, in seconds, rounded
# to the first slice value.
#
# User friendly output: use text representation of UTC time.
#

import sys
import os
from pathlib import Path
import ip2as
import rsv_log_parse
import pandas as pd
import traceback
import top_as
import time
import calendar
import csv
import rsv_arguments



def usage():
    print("Usage: python rsv_https.py <output_dir> [<list of AS] <csv_file> ... <csv_file>\n")
    print("This script will load the csv files, and produce output files:")
    print("   <output_dir>/https_metrics.csv: table of https usage per 1 hour interval.")
    print("   <output_dir>/https_5min_ASnnnn.csv: table of https by 5 minute interval for ASnnnn.")

def get_time_hour(first_time):
    fth = int(first_time/3600)
    ft = fth*3600
    return ft

class https_slice:
    def __init__(self):
        self.nb_uid = 0
        self.nb_https = 0

class https_query:
    def __init__(self, uid, query_time, query_AS):
        self.uid = uid
        self.query_time = query_time
        self.query_AS = query_AS
        self.has_https = False
        self.has_a = False
        self.has_aaaa = False

class https_queries:
    def __init__(self):
        self.uid_list = dict()
        self.first_time = 0
        self.tried = 0


    def add_query(self, uid, query_time, query_AS, rr_type):
        if not uid in self.uid_list:
            self.uid_list[uid] = https_query(uid, query_time, query_AS)
        if rr_type == 'HTTPS':
            self.uid_list[uid].has_https = True
        elif rr_type == 'A':
            self.uid_list[uid].has_a = True
        elif rr_type == 'AAAA':
            self.uid_list[uid].has_aaaa = True
        if self.first_time == 0 or self.first_time > query_time:
            self.first_time = query_time
    
    # load the input files
    def load_csv_log(self, saved_file):
        nb_events = 0
        with open(saved_file, newline='') as csvfile:
            rsv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            is_first = True
            is_second = True
            header_row = [ 'query_time', 'query_AS', 'query_user_id', 'rr_type' ]
            header_index = [ -1, -1, -1, -1 ]

            for row in rsv_reader:
                if is_first:
                    # print(",".join(row))
                    for i in range(0, len(header_row)):
                        for x in range(0, len(row)):
                            if row[x] == header_row[i]:
                            #   print("row[" + str(x) + "](" + str(row[x]) + ") == " + header_row[i])
                                header_index[i] = x
                                break
                            #else:
                            #    print(row[x] + " != " + header_row[i])
                        if header_index[i] < 0:
                            print("Could not find " + header_row[i] + " in " + ','.join(row))
                            exit(-1)
                    is_first = False
                else:
                    if (is_second):
                        #print(",".join(row))
                        #for i in range(0, len(header_row)):
                        #    print(str(i) + ": x[" + header_row[i] + "] = " + str(row[header_index[i]]))
                        is_second = False
                    query_time = float(row[header_index[0]])
                    query_AS = row[header_index[1]]
                    uid = row[header_index[2]]
                    rr_type = row[header_index[3]]
                    self.add_query(uid, query_time, query_AS, rr_type)
                    nb_events += 1

        return nb_events

    def get_slice_time(self, query_time, slice_duration, debug=False):
        slice_nb = int((query_time - self.first_time)/slice_duration)
        if debug:
            print("(" + str(query_time) + " - " + str(self.first_time) + ") / " + str(slice_duration) + " = " + str(slice_nb))
        slice_time = self.first_time + slice_nb*slice_duration
        return slice_time
    
    def get_slices(self, slice_duration, query_AS):
        slices = dict()
        has_AS = query_AS.startswith("AS")
        nb_events = 0
        nb_processed = 0


        for uid in self.uid_list:
            event = self.uid_list[uid]
            nb_events += 1
            if has_AS and event.query_AS != query_AS:
                continue
            nb_processed += 1
            slice_time = self.get_slice_time(event.query_time, slice_duration)
            if not slice_time in slices:
                slices[slice_time] = https_slice()
            slices[slice_time].nb_uid += 1
            if event.has_https: 
                slices[slice_time].nb_https += 1

        print("Processed " + str(nb_processed) + " out of " + str(nb_events) + " events.")
        print("Found " + str(len(slices)) + " slices.")

        v = []
        for slice_time in slices:
            if slices[slice_time].nb_uid > 0:
                https_metric = slices[slice_time].nb_https/slices[slice_time].nb_uid
                x = [ slice_time, https_metric, slices[slice_time].nb_https, slices[slice_time].nb_uid]
                v.append(x)

        v.sort(key=lambda x:x[0])

        df = pd.DataFrame(v, columns=["slice_time", "https_metric", "https", "uids"])

        return df

    def get_AS_summary(self, threshold=10000):
        AS_list = dict()

        for uid in self.uid_list:
            event = self.uid_list[uid]
            if not event.query_AS in AS_list:
                AS_list[event.query_AS] =  https_slice()
            AS_list[event.query_AS].nb_uid += 1
            if event.has_https: 
                AS_list[event.query_AS].nb_https += 1

        v = []
        for query_AS in AS_list:
            if AS_list[query_AS].nb_uid >= threshold:
                https_metric = AS_list[query_AS].nb_https/AS_list[query_AS].nb_uid
                x = [ query_AS, https_metric, AS_list[query_AS].nb_https, AS_list[query_AS].nb_uid]
                v.append(x)

        v.sort(key=lambda x:x[3], reverse=True)

        df = pd.DataFrame(v, columns=["query_AS", "https_metric", "https", "uids"])

        return df


# Main program
if __name__ == "__main__":
    time_start = time.time()
    if len(sys.argv) < 3:
        usage()
        exit(-1)

    output_dir = sys.argv[1]
    as_list = rsv_arguments.parse_AS_list(sys.argv[2:])
    csv_files, has_error = rsv_arguments.parse_file_list(sys.argv[2 + len(as_list):], [ ".csv"])
    if has_error:
        print("Invalid list of input files.")
        usage()
        exit(-1)

    hq = https_queries()

    for csv_file in csv_files:
        nb_events = hq.load_csv_log(csv_file)
        print(csv_file + ": " + str(nb_events) + " events.")
        first_hour = get_time_hour(hq.first_time)

    print("loaded " + str(len(hq.uid_list)) + " unique ids.")
    hq.first_time = get_time_hour(hq.first_time)
    print("Start time: " + str(hq.first_time) + " (" + time.asctime(time.gmtime(hq.first_time)) + ")")

    metric_df = hq.get_slices(3600, "")
    metric_file = os.path.join(output_dir, "https_metric.csv" )
    metric_df.to_csv(metric_file, sep=",")
    print("Saved: " + str(metric_df.shape[0]) + " time slices in " + metric_file)

    as_df = hq.get_AS_summary()
    as_file = os.path.join(output_dir, "https_as_list.csv" )
    as_df.to_csv(as_file, sep=",")
    print("Saved: " + str(as_df.shape[0]) + " AS in " + as_file)

    for asn in as_list:
        asn_df = hq.get_slices(300, asn)
        asn_file = os.path.join(output_dir, "https_" + asn + ".csv" )
        asn_df.to_csv(asn_file, sep=",")
        print("Saved: " + str(asn_df.shape[0]) + " time slices in " + asn_file)


