
# RDAP access:
# ripe: https://rdap.db.ripe.net/autnum/3243
# arin: https://rdap.arin.net/registry/autnum/20115
# lacnic: https://rdap.lacnic.net/rdap/autnum/7303 (rate limit exceeded after 1 query!)
# afrinic: https://rdap.afrinic.net/rdap/autnum/37020
# apnic: https://rdap.apnic.net/autnum/17676


import json
import urllib.request
import time
import top_as

def filter_bgp_name(bgp_name):
    if bgp_name[-6:].startswith(" -- "):
        bgp_name = bgp_name[:-6]
    return bgp_name

def crack_json_fn(data):
    success = False
    as_name = ""
    if 'entities' in data:
        x1 = data['entities']
        for x2 in x1:
            if 'vcardArray' in x2:
                x20 = x2['vcardArray']
                if len(x20) > 1:
                    x3 = x20[1]
                    kind_is_org=False
                    fn_name=""
                    for x4 in x3:
                        if len(x4) > 3:
                           if x4[0] =='kind' and x4[2]=='text' and (x4[3]=='org' or x4[3]=='group'):
                                kind_is_org = True
                           elif x4[0]=='fn' and x4[2]=='text':
                                fn_name=x4[3]
                        if len(fn_name) > 0 and kind_is_org:
                            break;
                    if len(fn_name) > 0 and kind_is_org:
                        as_name = fn_name
                        success = True
                        break
                else:
                    print("vcardArray is short: " + str(x20))
            else:
                print("No vcard array in " + str(x2))
    return success, as_name


def get_as_name(rdap_url, asn, bgp_name):
    as_name = ""
    success = False
    if asn.startswith("AS"):
        as_url = rdap_url + asn[2:]
        try:
            with urllib.request.urlopen(as_url) as url:
                data = json.load(url)
                print("loaded data from " + as_url)
                if 'name' in data:
                    t_name = data['name']
                    if t_name == asn or t_name == asn[2:] or t_name == ("ASN" + asn[2:]) or t_name.endswith("AFRINIC"):
                        print("Found " + asn + ", name was " + t_name + ". Need to look again.")
                    else:
                        as_name = t_name
                        success = True
                else:
                    print("No name property for " + asn + ". Need to look again")
                if (not success):
                    if asn in top_as.TopAS:
                        x = top_as.TopAS[asn]
                        print("Using Top AS name: ", x[0])
                        as_name = x[0]
                        success = True
                    else:
                        success,j_name =  crack_json_fn(data)
                        if success:
                            print("Cracked name from JSON: " + j_name)
                            as_name = j_name
                        else:
                            as_name = filter_bgp_name(bgp_name)
                            if len(as_name) == 0:
                                as_name = asn
                                print("No bgp name either, using: " + as_name)
                            else:
                                print("Use BGP name: " + as_name)
                            success = True
        except Exception as exc:
            print("Fail: " + as_url + ": " + str(exc))
    return success, as_name

def get_as_name_by_region(region, asn, as_name):
    if region == 'EUR':
        rdap_url = "https://rdap.db.ripe.net/autnum/"
    elif region == 'AP':
        rdap_url = "https://rdap.apnic.net/autnum/"
    else:
        rdap_url = "https://rdap.arin.net/registry/autnum/"

    success, as_name = get_as_name(rdap_url, asn, as_name)
    print(asn + ": " + as_name + ", " + str(success))
    time.sleep(1)
    return success, as_name

