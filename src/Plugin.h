#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin::Flow_Meter {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;
    void HookSetupAnalyzerTree(zeek::Connection* conn) override;
} plugin;

} // namespace zeek::plugin::Flow_Meter
