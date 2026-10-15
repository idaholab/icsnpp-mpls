// Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

////////////////////////////////////////////////////////////////////////////////
//
// ICSNPP - MPLS
//
// This file implements the Zeek packet analyzer for MPLS label stacks.
//
// Melanie Pierce, Idaho National Lab, November 2026
// melanie.pierce@inl.gov
//
////////////////////////////////////////////////////////////////////////////////

#include "MPLSLogging.h"
#include <zeek/Event.h>
#include <zeek/Type.h>
#include "zeek/Val.h"
#include <zeek/Func.h>
using namespace zeek::packet_analysis::MPLSLogger;

MPLSLogger::MPLSLogger() : zeek::packet_analysis::Analyzer("MPLSLogger") {}

bool MPLSLogger::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    // Skip the MPLS label stack.
    bool end_of_stack = false;
    static uint64_t count = 0;
    printf("MPLS analyzer entry #%llu\n",
       (unsigned long long)++count);
    zeek::IntrusivePtr<zeek::RecordType> mpls_header = zeek::id::find_type<zeek::RecordType>("MPLSLogger::MPLS_Header");
    zeek::IntrusivePtr<zeek::RecordVal> mpls_record = zeek::make_intrusive<zeek::RecordVal>(mpls_header);
    zeek::EventHandlerPtr event = zeek::event_registry->Lookup("MPLSLogger::log_mpls_header");

    IntrusivePtr<Type> count_type = base_type(TYPE_COUNT);
    IntrusivePtr<VectorType> vec_type = make_intrusive<VectorType>(count_type);
    IntrusivePtr<Type> bool_type = base_type(TYPE_BOOL);
    IntrusivePtr<VectorType> vec_type_bool = make_intrusive<VectorType>(bool_type);
    zeek::IntrusivePtr<zeek::VectorVal> labels =
    zeek::make_intrusive<zeek::VectorVal>(vec_type);
    zeek::IntrusivePtr<zeek::VectorVal> exps = zeek::make_intrusive<zeek::VectorVal>(vec_type);
    zeek::IntrusivePtr<zeek::VectorVal> bos_indicator = zeek::make_intrusive<zeek::VectorVal>(vec_type_bool);
    zeek::IntrusivePtr<zeek::VectorVal> ttls = zeek::make_intrusive<zeek::VectorVal>(vec_type);

    while (!end_of_stack) {
        if (  len <= 4 ) {
            Weird("truncated_link_header", packet);
            return false;
        }
        printf("data ptr = %p\n", (void*)data);

        uint32_t header =
            ((uint32_t)data[0] << 24) |
            ((uint32_t)data[1] << 16) |
            ((uint32_t)data[2] << 8)  |
            ((uint32_t)data[3]);

        uint32_t label = (header >> 12) & 0xFFFF;
        uint8_t exp = (header >> 9) & 0x7;
        bool bos = (bool)((header >> 8) & 0x01);
        uint8_t ttl = header & 0xFF;

        end_of_stack = bos;
        
        printf("MPLS Header: label=%u, exp=%u, bos=%d, ttl=%u\n", label, exp, end_of_stack, ttl);
        

        labels->Assign(labels->Size(), make_intrusive<CountVal>(label));
        exps->Assign(exps->Size(), make_intrusive<CountVal>(exp));
        bos_indicator->Assign(bos_indicator->Size(), make_intrusive<BoolVal>(bos));
        ttls->Assign(ttls->Size(), make_intrusive<CountVal>(ttl));
        data += 4;
        len -= 4;
    }

    printf("Exited loop. end_of_stack=%d\n", end_of_stack);

    double ts = static_cast<double>(packet->ts.tv_sec) +
                static_cast<double>(packet->ts.tv_usec) / 1e6;

    mpls_record->Assign(0, zeek::make_intrusive<zeek::TimeVal>(ts));
    mpls_record->Assign(1, labels);
    mpls_record->Assign(2, exps);
    mpls_record->Assign(3, bos_indicator);
    mpls_record->Assign(4, ttls);

    zeek::Args args;
    args.push_back(mpls_record);

    event_mgr.Enqueue(event, args);

    printf("data ptr = %p\n", (void*)data);

    // According to RFC3032 the encapsulated protocol is not encoded.
    // We use the configured default analyzer.
    return ForwardPacket(len, data, packet);
}
