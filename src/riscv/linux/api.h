# pragma once

#include <inttypes.h>

#include <cpuinfo.h>
#include <cpuinfo/common.h>

#if CPUINFO_ARCH_RISCV || CPUINFO_ARCH_RISCV64
    /* arch/riscv/include/uapi/asm/hwcap.h */
    #define CPUINFO_RISCV_LINUX_FEATURE_A                UINT32_C(0x00000001)
    #define CPUINFO_RISCV_LINUX_FEATURE_C                UINT32_C(0x00000004)
    #define CPUINFO_RISCV_LINUX_FEATURE_D                UINT32_C(0x00000008)
    #define CPUINFO_RISCV_LINUX_FEATURE_F                UINT32_C(0x00000020)
    #define CPUINFO_RISCV_LINUX_FEATURE_I                UINT32_C(0x00000100)
    #define CPUINFO_RISCV_LINUX_FEATURE_M                UINT32_C(0x00001000)
#endif

#define CPUINFO_RISCV_LINUX_VALID_ARCHITECTURE           UINT32_C(0x00010000)
#define CPUINFO_RISCV_LINUX_VALID_IMPLEMENTER            UINT32_C(0x00020000)
#define CPUINFO_RISCV_LINUX_VALID_PROCESSOR              UINT32_C(0x00040000)
#define CPUINFO_RISCV_LINUX_VALID_FEATURES               UINT32_C(0x00080000)

struct cpuinfo_riscv_linux_processor {
    uint32_t architecture_version;
    uint32_t features;
    enum cpuinfo_vendor vendor;
    enum cpuinfo_uarch uarch;
    uint32_t uarch_index;
    uint32_t package_id;
    uint32_t package_leader_id;
    uint32_t package_processor_count;
    uint32_t system_processor_id;
    uint32_t flags;
};

CPUINFO_INTERNAL bool cpuinfo_riscv_linux_parse_proc_cpuinfo(
        uint32_t max_processors_count,
        struct cpuinfo_riscv_linux_processor processors[restrict static max_processors_count]);

#if CPUINFO_ARCH_RISCV || CPUINFO_ARCH_RISCV64
    CPUINFO_INTERNAL void cpuinfo_riscv_linux_hwcap_from_getauxval(
		uint32_t hwcap[restrict static 1]);

    CPUINFO_INTERNAL void cpuinfo_riscv_linux_decode_isa_from_proc_cpuinfo(
		uint32_t features,
		struct cpuinfo_riscv_isa isa[restrict static 1]);
#endif

CPUINFO_INTERNAL void cpuinfo_riscv_linux_count_cluster_processors(
    uint32_t max_processors,
    struct cpuinfo_riscv_linux_processor processors[restrict static max_processors]);

extern CPUINFO_INTERNAL const uint32_t* cpuinfo_linux_cpu_to_uarch_index_map;
