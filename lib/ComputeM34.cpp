/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <string.h>
#include <algorithm>
#include "DnsStats.h"
#include "ComputeM34.h"

static char const * leaked_local_names = "(local host names)";

bool metric34_line_is_bigger(metric34_line_t x, metric34_line_t y)
{
    bool ret = false;

    if (x.frequency > y.frequency)
    {
        ret = true;
    }
    else if (x.frequency == y.frequency)
    {
        ret = CaptureSummary::compare_string(x.domain, y.domain) > 0;
    }

    return (ret);
}

bool metric8_line_is_bigger(metric8_line_t x, metric8_line_t y)
{
    bool ret = false;

    if (x.frequency > y.frequency)
    {
        ret = true;
    }
    else if (x.frequency == y.frequency)
    {
        ret = x.opt_code < y.opt_code;
    }

    return (ret);
}

static double scalar_metric_from_extract(std::vector<CaptureLine*> * extract)
{
    double ret = 0;
    uint64_t total = 0;
    uint64_t support = 0;

    for (size_t i = 0; i < extract->size(); i++) {
        total += (*extract)[i]->count;
        if ((*extract)[i]->key_type == 0 && (*extract)[i]->key_number == 1) {
            support += (*extract)[i]->count;
        }
    }

    if (total > 0) {
        ret = (double)support;
        ret /= (double)total;
    }

    return ret;
}

static double scalar_metric_from_capture(CaptureSummary * cs, uint32_t table_id)
{
    std::vector<CaptureLine*> extract;
    cs->Extract(DnsStats::GetTableName(table_id), &extract);

    return scalar_metric_from_extract(&extract);
}


void GetStringM_X(CaptureSummary * cs, uint32_t table_id,
    std::vector<metric34_line_t>* mstring_x, uint64_t nbqueries, double min_share)
{
    if (nbqueries > 0)
    {
        std::vector<CaptureLine *> extract;

        cs->Extract(
            DnsStats::GetTableName(table_id), &extract);
        mstring_x->reserve(extract.size());

        for (size_t i = 0; i < extract.size(); i++)
        {
            metric34_line_t line;

            line.domain[strlen(extract[i]->key_value)] = 0;
            line.frequency = ((double)extract[i]->count) / ((double)nbqueries);

            if (extract.size() < 8 || line.frequency >= min_share)
            {
                memcpy(line.domain, extract[i]->key_value, strlen(extract[i]->key_value));
                mstring_x->push_back(line);
            }
        }

        std::sort(mstring_x->begin(), mstring_x->end(), metric34_line_is_bigger);
    }
}

ComputeM3::ComputeM3()
    :
    nb_rootqueries(0),
    m3_1(0),
    m3_2(0),
    m33_4(0),
    m33_5(0),
    m3_4_1(0),
    m3_5(0),
    m3_6(0)
{
}

ComputeM3::~ComputeM3()
{
}

bool ComputeM3::Load(char const * single_file_name)
{
    return cs.Load(single_file_name);
}

bool ComputeM3::LoadMultipleFiles(char const ** in_files, int nb_files)
{
    return (nb_files == 1)?Load(in_files[0]):cs.Merge(nb_files, in_files);
}

bool ComputeM3::Compute()
{
    bool ret;
    
    ret = GetM3_1() &&
        GetM3_2() &&
        GetM33_1() &&
        GetM33_2() &&
        GetM33_3();

    if (ret) {
        ret = GetM33_5();
    }

    if (ret) {
        m33_4 = m3_1;

        for (size_t i = 0; ret && i < m33_1.size(); i++) {
            /* Check for data collection bug */
            if (DnsStats::IsRfc6761Tld((uint8_t *)(m33_1[i].domain), strlen(m33_1[i].domain))) {
                m33_4 -= m33_1[i].frequency;
            }
        }

        for (size_t i = 0; ret && i < m33_2.size(); i++) {
            m33_4 -= m33_2[i].frequency;
        }

        for (size_t i = 0; ret && i < m33_3.size(); i++) {
            m33_4 -= m33_3[i].frequency;
        }

        if (m33_4 < 0) {
            m33_4 = 0;
        }
    }

    ret &= GetM3_4();
    ret &= GetM3_5();
    ret &= GetM3_6();

    ret &= GetM3_7();

    return ret;
}

bool ComputeM3::Write(FILE * F_out, char const* date, char const* version)
{
    bool ret = true;

    ret = (fprintf(F_out, "M3.1,%s,%s, , %6f,\n", date, version, m3_1) > 0 &&
        fprintf(F_out, "M3.2,%s,%s, , %6f,\n", date, version, m3_2) > 0);

    for (size_t i = 0; ret && i < m33_1.size(); i++)
    {
        /* This is the RFC 6761 table. We need a check to fix a data collection bug. */
        if (DnsStats::IsRfc6761Tld((uint8_t *)(m33_1[i].domain), strlen(m33_1[i].domain))) {
            ret = fprintf(F_out, "M3.3.1,%s,%s, %s, %6f,\n", date, version, m33_1[i].domain, m33_1[i].frequency) > 0;
        }
    }

    for (size_t i = 0; ret && i < m33_2.size(); i++)
    {
        ret = fprintf(F_out, "M3.3.2,%s,%s, %s, %6f,\n", date, version, m33_2[i].domain, m33_2[i].frequency) > 0;
    }

    for (size_t i = 0; ret && i < m33_3.size(); i++)
    {
        ret = fprintf(F_out, "M3.3.3,%s,%s, %s, %6f,\n", date, version, m33_3[i].domain, m33_3[i].frequency) > 0;
    }

    if (ret)
    {
        ret = fprintf(F_out, "M3.3.4,%s,%s, , %6f,\n", date, version, (m33_4 > 0) ? m33_4 : 0);
    }

    if (ret && m33_5 > 0)
    {
        ret = fprintf(F_out, "M3.3.5,%s,%s, , %6f,\n", date, version, m33_5);
    }

    if (ret) {
        ret = fprintf(F_out, "M3.4.1,%s,%s, , %6f,\n", date, version, m3_4_1) > 0;
    }

    for (size_t i = 0; ret && i < m3_4_2.size(); i++) {
        ret = fprintf(F_out, "M3.4.2,%s,%s, %d, %6f,\n", date, version,
            m3_4_2[i].opt_code,
            m3_4_2[i].frequency) > 0;
    }

    if (ret) {
        ret = fprintf(F_out, "M3.5,%s,%s, , %6f,\n", date, version, m3_5) > 0;
    }

    if (ret) {
        ret = fprintf(F_out, "M3.6,%s,%s, , %6f,\n", date, version, m3_6) > 0;
    }

    if (ret) {
        for (size_t i = 0; ret && i < m3_7.size(); i++)
        {
            ret = fprintf(F_out, "M3.7,%s,%s, %s, %6f,\n", date, version, m3_7[i].domain, m3_7[i].frequency) > 0;
        }
    }

    return ret;
}

void ComputeM3::GetM3_X(uint32_t table_id,
    std::vector<metric34_line_t>* mstring_x, double min_share)
{
    GetStringM_X(&cs, table_id, mstring_x, nb_rootqueries, min_share);
}


bool ComputeM3::GetM3_1()
{
    bool ret = true;
    uint64_t nb_noerror = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_root_QR), 0);
    uint64_t nb_nxdomain = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_root_QR), 3);
    nb_rootqueries = nb_noerror + nb_nxdomain;

    if (nb_rootqueries > 0)
    {
        m3_1 = (double)nb_nxdomain;
        m3_1 /= (double)nb_rootqueries;
    }
    else
    {
        m3_1 = 0;
        ret = false;
    }

    return ret;
}

bool ComputeM3::GetM3_2()
{
    bool ret = true;
    uint64_t nb_useful = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_UsefulQueries), 1);
    uint64_t nb_useless = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_UsefulQueries), 0);
    uint64_t total = nb_useful + nb_useless;

    if (total > 0)
    {
        m3_2 = (double)nb_useless;
        m3_2 /= (double)total;
    }
    else
    {
        m3_2 = 0;
        ret = false;
    }

    return ret;
}

bool ComputeM3::GetM33_1()
{
    bool ret = true;
    GetM3_X(REGISTRY_DNS_RFC6761TLD, &m33_1, 0);

    return ret;
}

bool ComputeM3::GetM33_2()
{
    bool ret = true;
    GetM3_X(REGISTRY_DNS_LeakedTLD, &m33_2, 0.001);

    return ret;
}

void ComputeM3::GetM33_3_pattern(int registry_id, char const * pattern_name)
{
    uint64_t nb = cs.GetCountByNumber(DnsStats::GetTableName(registry_id), 0);
    if (nb > 0) {
        metric34_line_t line;
        size_t len = strlen(pattern_name);

        if (len + 1 > sizeof(line.domain)) {
            len = sizeof(line.domain) - 1;
        }

        memcpy(line.domain, pattern_name, len);
        line.domain[len] = 0;
        line.frequency = ((double)nb) / ((double)nb_rootqueries);
        m33_3.push_back(line);
    }
}

bool ComputeM3::GetM33_3()
{
    bool ret = true;
    if (nb_rootqueries <= 0)
    {
        ret = false;
    }
    else
    {
        std::vector<CaptureLine *> extract;
        std::vector<CaptureLine*> extract_chp;

        cs.Extract(
            DnsStats::GetTableName(REGISTRY_DNS_LeakByLength), &extract);
        cs.Extract(
            DnsStats::GetTableName(REGISTRY_CHROMIUM_PROBES), &extract_chp);

        m33_3.reserve(extract.size() + extract_chp.size());

        for (size_t i = 0; i < extract.size(); i++)
        {
            metric34_line_t line;
            size_t indx = 0;

            line.domain[indx++] = 'l';
            line.domain[indx++] = 'e';
            line.domain[indx++] = 'n';
            line.domain[indx++] = 'g';
            line.domain[indx++] = 't';
            line.domain[indx++] = 'h';
            line.domain[indx++] = '_';
            /* Length is between 0 and 64, and itoa is not portable */
            if (extract[i]->key_number < 10)
            {
                line.domain[indx++] = '0' + extract[i]->key_number;
            }
            else
            {
                line.domain[indx++] = '0' + extract[i]->key_number / 10;
                line.domain[indx++] = '0' + extract[i]->key_number % 10;
            }
            line.domain[indx++] = 0;
            line.frequency = ((double)extract[i]->count) / ((double)nb_rootqueries);

            if (extract.size() < 8 || line.frequency >= 0.001)
            {
                m33_3.push_back(line);
            }
        }

        for (size_t i = 0; i < extract_chp.size(); i++)
        {
            metric34_line_t line;
            size_t indx = 0;

            line.domain[indx++] = 'c';
            line.domain[indx++] = 'h';
            line.domain[indx++] = 'p';
            line.domain[indx++] = '_';
            /* Length is between 0 and 64, and itoa is not portable */
            if (extract_chp[i]->key_number < 10)
            {
                line.domain[indx++] = '0' + extract_chp[i]->key_number;
            }
            else
            {
                line.domain[indx++] = '0' + extract_chp[i]->key_number / 10;
                line.domain[indx++] = '0' + extract_chp[i]->key_number % 10;
            }
            line.domain[indx++] = 0;
            line.frequency = ((double)extract_chp[i]->count) / ((double)nb_rootqueries);

            if (extract_chp.size() < 8 || line.frequency >= 0.001)
            {
                m33_3.push_back(line);
            }
        }

        /* Add line for binary pattern if present */
        GetM33_3_pattern(REGISTRY_DNS_LEAK_BINARY, "binary");

        /* Add line for bad syntax pattern if present */
        GetM33_3_pattern(REGISTRY_DNS_LEAK_SYNTAX, "bad_syntax");

        /* Add line for bad syntax pattern if present */
        GetM33_3_pattern(REGISTRY_DNS_LEAK_IPV4, "ipv4");

        /* Add line for bad syntax pattern if present */
        GetM33_3_pattern(REGISTRY_DNS_LEAK_NUMERIC, "numeric");

        std::sort(m33_3.begin(), m33_3.end(), metric34_line_is_bigger);
    }

    return ret;
}

bool ComputeM3::GetM33_5()
{
    bool ret = true;
    uint64_t nb_useful = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_UsefulQueries), 2);
    uint64_t nb_useless = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_UsefulQueries), 3);
    uint64_t total = nb_useful + nb_useless;

    if (total > 0)
    {
        m33_5 = (double)nb_useless;
        m33_5 /= (double)total;
    }
    else
    {
        m33_5 = 0;
    }

    return ret;
}

bool ComputeM3::GetM3_4()
{
    return ComputeM8::ComputeEdnsMetrics(&cs, &m3_4_1, &m3_4_2);
}

bool ComputeM3::GetM3_5()
{
    bool ret = true;

    m3_5 = scalar_metric_from_capture(&cs, REGISTRY_DNSSEC_Client_Usage);

    return ret;
}

bool ComputeM3::GetM3_6()
{
    bool ret = true;

    m3_6 = scalar_metric_from_capture(&cs, REGISTRY_QNAME_MINIMIZATION_Usage);

    return ret;
}

bool ComputeM3::GetM3_7()
{
    bool ret = true;

    GetM3_X(REGISTRY_DNS_LEAK_2NDLEVEL, &m3_7, 0.001);

    return ret;
}

ComputeM4::ComputeM4()
    :
    nb_userqueries(0),
    nb_nondelegated(0),
    nb_delegated(0),
    m4_1(0),
    m4_4(0),
    m4_5(0)
{
}

ComputeM4::~ComputeM4()
{
}

bool ComputeM4::Load(char const * single_file_name)
{
    return cs.Load(single_file_name);
}

bool ComputeM4::LoadMultipleFiles(char const ** in_files, int nb_files)
{
    return (nb_files == 1) ? Load(in_files[0]) : cs.Merge(nb_files, in_files);
}

bool ComputeM4::Compute()
{
    bool ret = GetM4_1() &&
        GetM4_2() &&
        GetM4_3();

    if (ret)
    {
        m4_4 = 1.0 - m4_1;

        for (size_t i = 0; ret && i < m4_2.size(); i++)
        {
            m4_4 -= m4_2[i].frequency;
        }

        for (size_t i = 0; ret && i < m4_3.size(); i++)
        {
            m4_4 -= m4_3[i].frequency;
        }

        if (m4_4 < 0)
        {
            m4_4 = 0;
        }
    }

    if (ret) 
    {
        ret = GetM4_DNSSEC();
    }


    return ret;
}

bool ComputeM4::Write(FILE * F_out, char const* date, char const* version)
{
    bool ret = fprintf(F_out, "M4.1,%s,%s, , %6f,\n", date, version, m4_1) > 0;

    for (size_t i = 0; ret && i < m4_2.size(); i++) {
        ret = fprintf(F_out, "M4.2,%s,%s, %s, %6f,\n", date, version, m4_2[i].domain, m4_2[i].frequency) > 0;
    }

    for (size_t i = 0; ret && i < m4_3.size(); i++) {
        ret = fprintf(F_out, "M4.3,%s,%s, %s, %6f,\n", date, version, m4_3[i].domain, m4_3[i].frequency) > 0;
    }

    if (ret) {
        ret = fprintf(F_out, "M4.4,%s,%s, , %6f,\n", date, version, m4_4) > 0;
    }

    if (ret) {
        ret = fprintf(F_out, "M4.5,%s,%s, , %6f,\n", date, version, m4_5) > 0;
    }
    /* Removing metric M4.6 until investigation completes */
#if 0
    if (ret) {
        ret = fprintf(F_out, "M4.6,%s,%s, , %6f,\n", date, version, m4_6) > 0;
    }
#endif

    return ret;
}

bool ComputeM4::GetM4_X(uint32_t table_id, std::vector<metric34_line_t>* mstring_x, double min_share)
{
    bool ret = true;
    /* compute using nb_userqueries */
    if (nb_userqueries > 0)
    {
        GetStringM_X(&cs, table_id, mstring_x, nb_userqueries, min_share);

    }
    else
    {
        ret = false;
    }

    return ret;
}

bool ComputeM4::GetM4_1()
{
    bool ret = true;

    nb_nondelegated = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_TLD_Usage_Count), 0);
    nb_delegated = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_TLD_Usage_Count), 1);
    nb_userqueries = nb_nondelegated + nb_delegated;

    if (nb_userqueries > 0)
    {
        m4_1 = (double)nb_delegated;
        m4_1 /= (double)nb_userqueries;
    }
    else
    {
        m4_1 = 0;
        ret = false;
    }

    return ret;
}

bool ComputeM4::GetM4_2()
{
    GetM4_X(REGISTRY_DNS_RFC6761_Usage, &m4_2, 0);

    return true;
}

bool ComputeM4::GetM4_3()
{
    bool ret = true;
    double min_val = 0;

    if (nb_userqueries > 0)
    {
        /*
        * We adjust the threshold to 1% of the non delegated TLD queries,
        * or 0.1% of total queries, whichever is lower.
        */
        min_val = (double)nb_nondelegated;
        min_val /= nb_userqueries;
        min_val /= 500;

        if (min_val > 0.001)
        {
            min_val = 0.001;
        }

        GetM4_X(REGISTRY_DNS_Frequent_TLD_Usage, &m4_3, min_val);

        /* Add the count of locally defined domains */
        std::vector<CaptureLine *> extract;

        cs.Extract(
            DnsStats::GetTableName(REGISTRY_DNS_Local_TLD_Usage_Count), &extract);

        if (extract.size() != 0)
        {
            metric34_line_t line;

            line.frequency = ((double)extract[0]->count) / ((double)nb_userqueries);

            if (line.frequency >= min_val)
            {
                memcpy(line.domain, leaked_local_names, strlen(leaked_local_names) + 1);
                m4_3.push_back(line);
                std::sort(m4_3.begin(), m4_3.end(), metric34_line_is_bigger);
            }
        }
    }
    else
    {
        ret = false;
    }

    return ret;
}

bool ComputeM4::GetM4_DNSSEC()
{
    bool ret = true;

    m4_5 = scalar_metric_from_capture(&cs, REGISTRY_DNSSEC_Client_Usage);
    /* Removing M4.6 for now, until investigation completes */
    /* m4_6 = scalar_metric_from_capture(&cs, REGISTRY_DNSSEC_Zone_Usage); */

    return ret;
}

ComputeM8::ComputeM8() :
    m8_1(0),
    m8_2_1(0),
    m8_3(0),
    m8_4(0)
{
}

ComputeM8::~ComputeM8()
{
}

bool ComputeM8::Load(char const * single_file_name)
{
    return cs.Load(single_file_name);
}

bool ComputeM8::LoadMultipleFiles(char const ** in_files, int nb_files)
{
    return (nb_files == 1) ? Load(in_files[0]) : cs.Merge(nb_files, in_files);
}

bool ComputeM8::Compute()
{
    bool ret = GetM8_1() &&
        GetM8_2() &&
        GetM8_3() &&
        GetM8_4();

    return ret;
}

bool ComputeM8::Write(FILE * F_out, char const* date, char const* version)
{
    bool ret = fprintf(F_out, "M8.1,%s,%s, %6f,\n", date, version, m8_1) > 0;

    if (ret) {
        ret = fprintf(F_out, "M8.2.1,%s,%s, , %6f,\n", date, version, m8_2_1) > 0;
    }

    for (size_t i = 0; ret && i < m8_2_2.size(); i++) {
        ret = fprintf(F_out, "M8.2.2,%s,%s, %d, %6f,\n", date, version,
            m8_2_2[i].opt_code,
            m8_2_2[i].frequency) > 0;
    }

    if (ret) {
        ret = fprintf(F_out, "M8.3,%s,%s, , %6f,\n", date, version, m8_3) > 0;
    }

    if (ret) {
        ret = fprintf(F_out, "M8.4,%s,%s, , %6f,\n", date, version, m8_4) > 0;
    }

    return ret;
}

bool ComputeM8::GetM8_1()
{
    bool ret = true;
    uint64_t nb_noerror = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_RCODES), 0);
    uint64_t nb_nxdomain = cs.GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_DNS_RCODES), 3);
    uint64_t nb_responses = (nb_noerror + nb_nxdomain) / 2;

    if (nb_responses > 0)
    {
        m8_1 = (double)nb_nxdomain;
        m8_1 /= (double)nb_responses;
    }
    else
    {
        m8_1 = 0;
        ret = false;
    }

    return ret;
}

bool ComputeM8::ComputeEdnsMetrics(CaptureSummary * cs, double * m_edns, std::vector<metric8_line_t> * m_edns_opt)
{
    bool ret = true;
    uint64_t nb_edns_opt_usage_ref = cs->GetCountByNumber(
        DnsStats::GetTableName(REGISTRY_EDNS_OPT_USAGE_REF), 0);
    *m_edns = scalar_metric_from_capture(cs, REGISTRY_EDNS_Client_Usage);

    if (nb_edns_opt_usage_ref > 0) {
        std::vector<CaptureLine *> extract;

        cs->Extract(
            DnsStats::GetTableName(REGISTRY_EDNS_OPT_USAGE), &extract);

        if (extract.size() > 0) {
            m_edns_opt->reserve(extract.size());

            for (size_t i = 0; i < extract.size(); i++)
            {
                metric8_line_t line;

                line.opt_code = extract[i]->key_number;
                line.frequency = ((double)extract[i]->count) / ((double)nb_edns_opt_usage_ref);

                if (extract.size() < 8 || line.frequency >= 0.001)
                {
                    m_edns_opt->push_back(line);
                }
            }

            std::sort(m_edns_opt->begin(), m_edns_opt->end(), metric8_line_is_bigger);
        }
    }

    return ret;
}

bool ComputeM8::GetM8_2()
{
    return ComputeEdnsMetrics(&cs, &m8_2_1, &m8_2_2);
}

bool ComputeM8::GetM8_3()
{
    bool ret = true;

    m8_3 = scalar_metric_from_capture(&cs, REGISTRY_DNSSEC_Client_Usage);

    return ret;
}

bool ComputeM8::GetM8_4()
{
    bool ret = true;

    m8_4 = scalar_metric_from_capture(&cs, REGISTRY_QNAME_MINIMIZATION_Usage);

    return ret;
}
