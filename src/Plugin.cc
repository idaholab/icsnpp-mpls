// Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

////////////////////////////////////////////////////////////////////////////////
//
// ICSNPP - MPLS
//
// This file registers the MPLS packet analyzer as a Zeek plugin.
//
// Melanie Pierce, Idaho National Lab, November 2026
// melanie.pierce@inl.gov
//
////////////////////////////////////////////////////////////////////////////////

#include <zeek/packet_analysis/Manager.h>
#include <zeek/packet_analysis/Component.h>
#include "MPLSLogging.h"



namespace plugin { namespace Zeek_MPLSLogger {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override
    {
        zeek::plugin::Configuration config;
        config.name = "Zeek::MPLSLogging";
        config.description = "Adds logging for MPLS headers";
        config.version.major = 1;
        config.version.minor = 0;

        // Register our replacement
        AddComponent(new zeek::packet_analysis::Component(
            "MPLSLogger",
            zeek::packet_analysis::MPLSLogger::MPLSLogger::Instantiate));

        return config;
    }

protected:
    void InitPostScript() override
    {
        zeek::plugin::Plugin::InitPostScript();

        const auto mpls = zeek::packet_mgr->GetComponentTag("MPLS");
        const auto mpls_logger = zeek::packet_mgr->GetComponentTag("MPLSLogger");
        zeek::packet_mgr->AddComponentMapping(mpls, mpls_logger);
        zeek::packet_mgr->DisableAnalyzer(mpls);
    }
};

Plugin plugin;

}}
