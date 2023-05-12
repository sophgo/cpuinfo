#include <inttypes.h>

#include <riscv/linux/api.h>

void cpuinfo_riscv_linux_decode_isa_from_proc_cpuinfo(
        uint32_t features,
        struct cpuinfo_riscv_isa isa[restrict static 1])
{
    if (features & CPUINFO_RISCV_LINUX_FEATURE_A) {
        isa->a = true;
    }
    if (features & CPUINFO_RISCV_LINUX_FEATURE_C) {
        isa->c = true;
    }
    if (features & CPUINFO_RISCV_LINUX_FEATURE_D) {
        isa->d = true;
    }
    if (features & CPUINFO_RISCV_LINUX_FEATURE_F) {
        isa->f = true;
    }
    #if CPUINFO_ARCH_RISCV
        if (features & CPUINFO_RISCV_LINUX_FEATURE_I) {
            isa->i = true;
        }
    #endif
    if (features & CPUINFO_RISCV_LINUX_FEATURE_M) {
        isa->m = true;
    }
}