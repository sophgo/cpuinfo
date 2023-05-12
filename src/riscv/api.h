#pragma once

#include <cpuinfo.h>
#include <cpuinfo/internal-api.h>

CPUINFO_INTERNAL void cpuinfo_riscv_decode_cache(
        enum cpuinfo_uarch uarch,
        struct cpuinfo_cache l1i[restrict static 1],
        struct cpuinfo_cache l1d[restrict static 1],
        struct cpuinfo_cache l2[restrict static 1]);

CPUINFO_INTERNAL uint32_t cpuinfo_riscv_compute_max_cache_size(
        const struct cpuinfo_processor processor[restrict static 1]);
