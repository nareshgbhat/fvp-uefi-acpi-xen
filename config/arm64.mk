CONFIG_ARM := y
CONFIG_ARM_64 := y
CONFIG_ARM_$(XEN_OS) := y

CONFIG_XEN_INSTALL_SUFFIX :=

CFLAGS += #-marm -march= -mcpu= etc

HAS_PL011 := y
HAS_NS16550 := y
HAS_ACPI := y

# Use only if calling $(LD) directly.
LDFLAGS_DIRECT += -EL

CONFIG_LOAD_ADDRESS ?= 0x80000000
