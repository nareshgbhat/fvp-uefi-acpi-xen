#include "efi.h"
#include <efi/efiprot.h>
#include <efi/efipciio.h>
#include <efi/efi-shared.h>
#include <public/xen.h>
#include <xen/compile.h>
#include <xen/ctype.h>
#include <xen/dmi.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/multiboot.h>
#include <xen/pci_regs.h>
#include <xen/pfn.h>
#if EFI_PAGE_SIZE != PAGE_SIZE
# error Cannot use xen/pfn.h here!
#endif
#include <xen/string.h>
#include <xen/stringify.h>
#include <xen/vga.h>
#include <asm/e820.h>
#include <asm/edd.h>
#define __ASSEMBLY__ /* avoid pulling in ACPI stuff (conflicts with EFI) */
#include <asm/fixmap.h>
#undef __ASSEMBLY__
#include <asm/msr.h>
#include <asm/processor.h>

/* Using SetVirtualAddressMap() is incompatible with kexec: */
#undef USE_SET_VIRTUAL_ADDRESS_MAP

#define SHIM_LOCK_PROTOCOL_GUID \
  { 0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} }

typedef EFI_STATUS
(/* _not_ EFIAPI */ *EFI_SHIM_LOCK_VERIFY) (
    IN VOID *Buffer,
    IN UINT32 Size);

typedef struct {
    EFI_SHIM_LOCK_VERIFY Verify;
} EFI_SHIM_LOCK_PROTOCOL;

extern char start[];
extern u32 cpuid_ext_features;


/* Variables supplied/used by shared EFI code. */
extern CHAR16 __initdata newline[];
extern EFI_BOOT_SERVICES *__initdata efi_bs;
extern SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdOut;
extern SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdErr;


static EFI_HANDLE __initdata efi_ih;


static UINT32 __initdata mdesc_ver;

static struct file __initdata cfg;
static struct file __initdata kernel;
static struct file __initdata ramdisk;
static struct file __initdata ucode;
static struct file __initdata xsm;

static multiboot_info_t __initdata mbi = {
    .flags = MBI_MODULES | MBI_LOADERNAME
};
static module_t __initdata mb_modules[3];


static void __init noreturn blexit(const CHAR16 *str)
{
    if ( str )
        PrintStr((CHAR16 *)str);
    PrintStr(newline);

    if ( cfg.addr )
        efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
    if ( kernel.addr )
        efi_bs->FreePages(kernel.addr, PFN_UP(kernel.size));
    if ( ramdisk.addr )
        efi_bs->FreePages(ramdisk.addr, PFN_UP(ramdisk.size));
    if ( ucode.addr )
        efi_bs->FreePages(ucode.addr, PFN_UP(ucode.size));
    if ( xsm.addr )
        efi_bs->FreePages(xsm.addr, PFN_UP(xsm.size));

    efi_bs->Exit(efi_ih, EFI_SUCCESS, 0, NULL);
    unreachable(); /* not reached */
}


/* generic routine for printing error messages */
static void __init PrintErrMesgExit(const CHAR16 *mesg, EFI_STATUS ErrCode)
{
    PrintErrMesg(mesg, ErrCode);
    blexit(mesg);
}

static void __init place_string(u32 *addr, const char *s)
{
    static char *__initdata alloc = start;

    if ( s && *s )
    {
        size_t len1 = strlen(s) + 1;
        const char *old = (char *)(long)*addr;
        size_t len2 = *addr ? strlen(old) + 1 : 0;

        alloc -= len1 + len2;
        /*
         * Insert new string before already existing one. This is needed
         * for options passed on the command line to override options from
         * the configuration file.
         */
        memcpy(alloc, s, len1);
        if ( *addr )
        {
            alloc[len1 - 1] = ' ';
            memcpy(alloc + len1, old, len2);
        }
    }
    *addr = (long)alloc;
}

/* Only call with non-config files. */
bool_t __init load_file(EFI_FILE_HANDLE dir_handle, CHAR16 *name,
                               struct file *file)
{
    EFI_PHYSICAL_ADDRESS max = min(1UL << (32 + PAGE_SHIFT),
                                   HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START);
    if ( read_file(dir_handle, name, file, max) )
    {
        mb_modules[mbi.mods_count].mod_start = file->addr >> PAGE_SHIFT;
        mb_modules[mbi.mods_count].mod_end = file->size;
        ++mbi.mods_count;
        return 1;
    }
    return 0;
}

static void __init edd_put_string(u8 *dst, size_t n, const char *src)
{
    while ( n-- && *src )
       *dst++ = *src++;
    if ( *src )
       PrintErrMesgExit(L"Internal error populating EDD info",
                    EFI_BUFFER_TOO_SMALL);
    while ( n-- )
       *dst++ = ' ';
}
#define edd_put_string(d, s) edd_put_string(d, ARRAY_SIZE(d), s)

static void __init setup_efi_pci(void)
{
    EFI_STATUS status;
    EFI_HANDLE *handles;
    static EFI_GUID __initdata pci_guid = EFI_PCI_IO_PROTOCOL;
    UINTN i, nr_pci, size = 0;
    struct efi_pci_rom *last = NULL;

    status = efi_bs->LocateHandle(ByProtocol, &pci_guid, NULL, &size, NULL);
    if ( status == EFI_BUFFER_TOO_SMALL )
        status = efi_bs->AllocatePool(EfiLoaderData, size, (void **)&handles);
    if ( !EFI_ERROR(status) )
        status = efi_bs->LocateHandle(ByProtocol, &pci_guid, NULL, &size,
                                      handles);
    if ( EFI_ERROR(status) )
        size = 0;

    nr_pci = size / sizeof(*handles);
    for ( i = 0; i < nr_pci; ++i )
    {
        EFI_PCI_IO *pci = NULL;
        u64 attributes;
        struct efi_pci_rom *rom, *va;
        UINTN segment, bus, device, function;

        status = efi_bs->HandleProtocol(handles[i], &pci_guid, (void **)&pci);
        if ( EFI_ERROR(status) || !pci || !pci->RomImage || !pci->RomSize )
            continue;

        status = pci->Attributes(pci, EfiPciIoAttributeOperationGet, 0,
                                 &attributes);
        if ( EFI_ERROR(status) ||
             !(attributes & EFI_PCI_IO_ATTRIBUTE_EMBEDDED_ROM) ||
             EFI_ERROR(pci->GetLocation(pci, &segment, &bus, &device,
                       &function)) )
            continue;

        DisplayUint(segment, 4);
        PrintStr(L":");
        DisplayUint(bus, 2);
        PrintStr(L":");
        DisplayUint(device, 2);
        PrintStr(L".");
        DisplayUint(function, 1);
        PrintStr(L": ROM: ");
        DisplayUint(pci->RomSize, 0);
        PrintStr(L" bytes at ");
        DisplayUint((UINTN)pci->RomImage, 0);
        PrintStr(newline);

        size = pci->RomSize + sizeof(*rom);
        status = efi_bs->AllocatePool(EfiRuntimeServicesData, size,
                                      (void **)&rom);
        if ( EFI_ERROR(status) )
            continue;

        rom->next = NULL;
        rom->size = pci->RomSize;

        status = pci->Pci.Read(pci, EfiPciIoWidthUint16, PCI_VENDOR_ID, 1,
                               &rom->vendor);
        if ( !EFI_ERROR(status) )
            status = pci->Pci.Read(pci, EfiPciIoWidthUint16, PCI_DEVICE_ID, 1,
                                   &rom->devid);
        if ( EFI_ERROR(status) )
        {
            efi_bs->FreePool(rom);
            continue;
        }

        rom->segment = segment;
        rom->bus = bus;
        rom->devfn = (device << 3) | function;
        memcpy(rom->data, pci->RomImage, pci->RomSize);

        va = (void *)rom + DIRECTMAP_VIRT_START;
        if ( last )
            last->next = va;
        else
            efi_pci_roms = va;
        last = rom;
    }

    efi_bs->FreePool(handles);
}

static int __init set_color(u32 mask, int bpp, u8 *pos, u8 *sz)
{
   if ( bpp < 0 )
       return bpp;
   if ( !mask )
       return -EINVAL;
   for ( *pos = 0; !(mask & 1); ++*pos )
       mask >>= 1;
   for ( *sz = 0; mask & 1; ++sz)
       mask >>= 1;
   if ( mask )
       return -EINVAL;
   return max(*pos + *sz, bpp);
}

extern const intpte_t __page_tables_start[], __page_tables_end[];
#define in_page_tables(v) ((intpte_t *)(v) >= __page_tables_start && \
                           (intpte_t *)(v) < __page_tables_end)

#define PE_BASE_RELOC_ABS      0
#define PE_BASE_RELOC_HIGHLOW  3
#define PE_BASE_RELOC_DIR64   10

extern const struct pe_base_relocs {
    u32 rva;
    u32 size;
    u16 entries[];
} __base_relocs_start[], __base_relocs_end[];

static void __init relocate_image(unsigned long delta)
{
    const struct pe_base_relocs *base_relocs;

    for ( base_relocs = __base_relocs_start; base_relocs < __base_relocs_end; )
    {
        unsigned int i, n;

        n = (base_relocs->size - sizeof(*base_relocs)) /
            sizeof(*base_relocs->entries);
        for ( i = 0; i < n; ++i )
        {
            unsigned long addr = xen_phys_start + base_relocs->rva +
                                 (base_relocs->entries[i] & 0xfff);

            switch ( base_relocs->entries[i] >> 12 )
            {
            case PE_BASE_RELOC_ABS:
                break;
            case PE_BASE_RELOC_HIGHLOW:
                if ( delta )
                {
                    *(u32 *)addr += delta;
                    if ( in_page_tables(addr) )
                        *(u32 *)addr += xen_phys_start;
                }
                break;
            case PE_BASE_RELOC_DIR64:
                if ( delta )
                {
                    *(u64 *)addr += delta;
                    if ( in_page_tables(addr) )
                        *(intpte_t *)addr += xen_phys_start;
                }
                break;
            default:
                blexit(L"Unsupported relocation type");
            }
        }
        base_relocs = (const void *)(base_relocs->entries + i + (i & 1));
    }
}



extern const s32 __trampoline_rel_start[], __trampoline_rel_stop[];
extern const s32 __trampoline_seg_start[], __trampoline_seg_stop[];

static void __init relocate_trampoline(unsigned long phys)
{
    const s32 *trampoline_ptr;

    trampoline_phys = phys;
    /* Apply relocations to trampoline. */
    for ( trampoline_ptr = __trampoline_rel_start;
          trampoline_ptr < __trampoline_rel_stop;
          ++trampoline_ptr )
        *(u32 *)(*trampoline_ptr + (long)trampoline_ptr) += phys;
    for ( trampoline_ptr = __trampoline_seg_start;
          trampoline_ptr < __trampoline_seg_stop;
          ++trampoline_ptr )
        *(u16 *)(*trampoline_ptr + (long)trampoline_ptr) = phys >> 4;
}

void EFIAPI __init noreturn
efi_start(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    static EFI_GUID __initdata loaded_image_guid = LOADED_IMAGE_PROTOCOL;
    static EFI_GUID __initdata gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    static EFI_GUID __initdata bio_guid = BLOCK_IO_PROTOCOL;
    static EFI_GUID __initdata devp_guid = DEVICE_PATH_PROTOCOL;
    static EFI_GUID __initdata shim_lock_guid = SHIM_LOCK_PROTOCOL_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_STATUS status;
    unsigned int i;
    CHAR16 *file_name = NULL, *cfg_file_name = NULL, *image_name = NULL;
    CHAR16 *section_name = NULL;
    union string cmdline = { NULL };
    UINTN cols, rows, depth, size, map_key, info_size, gop_mode = ~0;
    EFI_HANDLE *handles = NULL;
    EFI_SHIM_LOCK_PROTOCOL *shim_lock;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info;
    EFI_FILE_HANDLE dir_handle;
    union string section = { NULL }, name;
    struct e820entry *e;
    u64 efer;
    bool_t base_video = 0;
    bool_t load_ok = 0;

    efi_ih = ImageHandle;
    efi_bs = SystemTable->BootServices;
    efi_rs = SystemTable->RuntimeServices;
    efi_ct = SystemTable->ConfigurationTable;
    efi_num_ct = SystemTable->NumberOfTableEntries;
    efi_version = SystemTable->Hdr.Revision;
    efi_fw_vendor = SystemTable->FirmwareVendor;
    efi_fw_revision = SystemTable->FirmwareRevision;

    StdOut = SystemTable->ConOut;
    StdErr = SystemTable->StdErr ?: StdOut;

    status = efi_bs->HandleProtocol(ImageHandle, &loaded_image_guid,
                                    (void **)&loaded_image);
    if ( status != EFI_SUCCESS )
        PrintErrMesgExit(L"No Loaded Image Protocol", status);

    xen_phys_start = (UINTN)loaded_image->ImageBase;
    if ( (xen_phys_start + loaded_image->ImageSize - 1) >> 32 )
        blexit(L"Xen must be loaded below 4Gb.");
    if ( xen_phys_start & ((1 << L2_PAGETABLE_SHIFT) - 1) )
        blexit(L"Xen must be loaded at a 2Mb boundary.");
    trampoline_xen_phys_start = xen_phys_start;

    /* Get the file system interface. */
    dir_handle = get_parent_handle(loaded_image, &file_name);

    if ( !handle_cmdline(loaded_image, &cfg_file_name, &base_video, &image_name,
                   &section_name, &cmdline.w) )
        blexit(NULL);

    if (cmdline.w)
        place_string(&mbi.cmdline, w2s(&cmdline));

    section.w = section_name;

    if ( !base_video )
    {
        unsigned int best;

        for ( i = 0, size = 0, best = StdOut->Mode->Mode;
              i < StdOut->Mode->MaxMode; ++i )
        {
            if ( StdOut->QueryMode(StdOut, i, &cols, &rows) == EFI_SUCCESS &&
                 cols * rows > size )
            {
                size = cols * rows;
                best = i;
            }
        }
        if ( best != StdOut->Mode->Mode )
            StdOut->SetMode(StdOut, best);
    }

    PrintStr(L"Xen " __stringify(XEN_VERSION) "." __stringify(XEN_SUBVERSION)
             XEN_EXTRAVERSION " (c/s " XEN_CHANGESET ") EFI loader\r\n");

    relocate_image(0);

    if ( StdOut->QueryMode(StdOut, StdOut->Mode->Mode,
                           &cols, &rows) == EFI_SUCCESS )
    {
        vga_console_info.video_type = XEN_VGATYPE_TEXT_MODE_3;
        vga_console_info.u.text_mode_3.columns = cols;
        vga_console_info.u.text_mode_3.rows = rows;
        vga_console_info.u.text_mode_3.font_height = 16;
    }

    size = 0;
    status = efi_bs->LocateHandle(ByProtocol, &gop_guid, NULL, &size, NULL);
    if ( status == EFI_BUFFER_TOO_SMALL )
        status = efi_bs->AllocatePool(EfiLoaderData, size, (void **)&handles);
    if ( !EFI_ERROR(status) )
        status = efi_bs->LocateHandle(ByProtocol, &gop_guid, NULL, &size,
                                      handles);
    if ( EFI_ERROR(status) )
        size = 0;
    for ( i = 0; i < size / sizeof(*handles); ++i )
    {
        status = efi_bs->HandleProtocol(handles[i], &gop_guid, (void **)&gop);
        if ( EFI_ERROR(status) )
            continue;
        status = gop->QueryMode(gop, gop->Mode->Mode, &info_size, &mode_info);
        if ( !EFI_ERROR(status) )
            break;
    }
    if ( handles )
        efi_bs->FreePool(handles);
    if ( EFI_ERROR(status) )
        gop = NULL;

    if ( !read_config_file(&dir_handle, &cfg, cfg_file_name, &section,
                           file_name) )
        blexit(L"Unable to read configuration file.");

    name.s = get_value(&cfg, section.s, "kernel");
    if ( !name.s )
        blexit(L"No Dom0 kernel image specified.");
    place_string(&mb_modules[mbi.mods_count].string, name.s);
    truncate_string(name.s);
    load_ok = load_file(dir_handle, s2w(&name), &kernel);
    efi_bs->FreePool(name.w);
    if ( !load_ok )
        blexit(L"Unable to load Dom0 Kernel image.");

    if ( !EFI_ERROR(efi_bs->LocateProtocol(&shim_lock_guid, NULL,
                    (void **)&shim_lock)) &&
         (status = shim_lock->Verify(kernel.ptr, kernel.size)) != EFI_SUCCESS )
        PrintErrMesgExit(L"Dom0 kernel image could not be verified", status);

    name.s = get_value(&cfg, section.s, "ramdisk");
    if ( name.s )
    {
        place_string(&mb_modules[mbi.mods_count].string, name.s);
        truncate_string(name.s);
        load_ok = load_file(dir_handle, s2w(&name), &ramdisk);
        efi_bs->FreePool(name.w);
        if ( !load_ok )
            blexit(L"Unable to load ramdisk image.");
    }

    name.s = get_value(&cfg, section.s, "ucode");
    if ( !name.s )
        name.s = get_value(&cfg, "global", "ucode");
    if ( name.s )
    {
        microcode_set_module(mbi.mods_count);
        place_string(&mb_modules[mbi.mods_count].string, name.s);
        truncate_string(name.s);
        load_ok = load_file(dir_handle, s2w(&name), &ucode);
        efi_bs->FreePool(name.w);
        if ( !load_ok )
            blexit(L"Unable to load ucode image.");
    }

    name.s = get_value(&cfg, section.s, "xsm");
    if ( name.s )
    {
        place_string(&mb_modules[mbi.mods_count].string, name.s);
        truncate_string(name.s);
        load_ok = load_file(dir_handle, s2w(&name), &xsm);
        efi_bs->FreePool(name.w);
        if ( !load_ok )
            blexit(L"Unable to load ucode image.");
    }

    name.s = get_value(&cfg, section.s, "options");
    if ( name.s )
        place_string(&mbi.cmdline, name.s);
    /* Insert image name last, as it gets prefixed to the other options. */
    if ( image_name )
    {
        name.w = image_name;
        w2s(&name);
    }
    else
        name.s = "xen";
    place_string(&mbi.cmdline, name.s);

    cols = rows = depth = 0;
    if ( !base_video )
    {
        name.cs = get_value(&cfg, section.s, "video");
        if ( !name.cs )
            name.cs = get_value(&cfg, "global", "video");
        if ( name.cs && !strncmp(name.cs, "gfx-", 4) )
        {
            cols = simple_strtoul(name.cs + 4, &name.cs, 10);
            if ( *name.cs == 'x' )
                rows = simple_strtoul(name.cs + 1, &name.cs, 10);
            if ( *name.cs == 'x' )
                depth = simple_strtoul(name.cs + 1, &name.cs, 10);
            if ( *name.cs )
                cols = rows = depth = 0;
        }
    }

    efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
    cfg.addr = 0;

    dir_handle->Close(dir_handle);

    if ( gop && !base_video )
    {
        for ( i = size = 0; i < gop->Mode->MaxMode; ++i )
        {
            unsigned int bpp = 0;

            status = gop->QueryMode(gop, i, &info_size, &mode_info);
            if ( EFI_ERROR(status) )
                continue;
            switch ( mode_info->PixelFormat )
            {
            case PixelBitMask:
                bpp = hweight32(mode_info->PixelInformation.RedMask |
                                mode_info->PixelInformation.GreenMask |
                                mode_info->PixelInformation.BlueMask);
                break;
            case PixelRedGreenBlueReserved8BitPerColor:
            case PixelBlueGreenRedReserved8BitPerColor:
                bpp = 24;
                break;
            default:
                continue;
            }
            if ( cols == mode_info->HorizontalResolution &&
                 rows == mode_info->VerticalResolution &&
                 (!depth || bpp == depth) )
            {
                gop_mode = i;
                break;
            }
            if ( !cols && !rows &&
                 mode_info->HorizontalResolution *
                 mode_info->VerticalResolution > size )
            {
                size = mode_info->HorizontalResolution *
                       mode_info->VerticalResolution;
                gop_mode = i;
            }
        }
    }

    if ( mbi.cmdline )
        mbi.flags |= MBI_CMDLINE;
    /*
     * These must not be initialized statically, since the value must
     * not get relocated when processing base relocations below.
     */
    mbi.boot_loader_name = (long)"EFI";
    mbi.mods_addr = (long)mb_modules;

    place_string(&mbi.mem_upper, NULL);

    /* Collect EDD info. */
    BUILD_BUG_ON(offsetof(struct edd_info, edd_device_params) != EDDEXTSIZE);
    BUILD_BUG_ON(sizeof(struct edd_device_params) != EDDPARMSIZE);
    size = 0;
    status = efi_bs->LocateHandle(ByProtocol, &bio_guid, NULL, &size, NULL);
    if ( status == EFI_BUFFER_TOO_SMALL )
        status = efi_bs->AllocatePool(EfiLoaderData, size, (void **)&handles);
    if ( !EFI_ERROR(status) )
        status = efi_bs->LocateHandle(ByProtocol, &bio_guid, NULL, &size,
                                      handles);
    if ( EFI_ERROR(status) )
        size = 0;
    for ( i = 0; i < size / sizeof(*handles); ++i )
    {
        EFI_BLOCK_IO *bio;
        EFI_DEV_PATH_PTR devp;
        struct edd_info *info = boot_edd_info + boot_edd_info_nr;
        struct edd_device_params *params = &info->edd_device_params;
        enum { root, acpi, pci, ctrlr } state = root;

        status = efi_bs->HandleProtocol(handles[i], &bio_guid, (void **)&bio);
        if ( EFI_ERROR(status) ||
             bio->Media->RemovableMedia ||
             bio->Media->LogicalPartition )
            continue;
        if ( boot_edd_info_nr < EDD_INFO_MAX )
        {
            info->device = 0x80 + boot_edd_info_nr; /* fake */
            info->version = 0x11;
            params->length = offsetof(struct edd_device_params, dpte_ptr);
            params->number_of_sectors = bio->Media->LastBlock + 1;
            params->bytes_per_sector = bio->Media->BlockSize;
            params->dpte_ptr = ~0;
        }
        ++boot_edd_info_nr;
        status = efi_bs->HandleProtocol(handles[i], &devp_guid,
                                        (void **)&devp);
        if ( EFI_ERROR(status) )
            continue;
        for ( ; !IsDevicePathEnd(devp.DevPath);
              devp.DevPath = NextDevicePathNode(devp.DevPath) )
        {
            switch ( DevicePathType(devp.DevPath) )
            {
                const u8 *p;

            case ACPI_DEVICE_PATH:
                if ( state != root || boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                switch ( DevicePathSubType(devp.DevPath) )
                {
                case ACPI_DP:
                    if ( devp.Acpi->HID != EISA_PNP_ID(0xA03) &&
                         devp.Acpi->HID != EISA_PNP_ID(0xA08) )
                        break;
                    params->interface_path.pci.bus = devp.Acpi->UID;
                    state = acpi;
                    break;
                case EXPANDED_ACPI_DP:
                    /* XXX */
                    break;
                }
                break;
            case HARDWARE_DEVICE_PATH:
                if ( state != acpi ||
                     DevicePathSubType(devp.DevPath) != HW_PCI_DP ||
                     boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                state = pci;
                edd_put_string(params->host_bus_type, "PCI");
                params->interface_path.pci.slot = devp.Pci->Device;
                params->interface_path.pci.function = devp.Pci->Function;
                break;
            case MESSAGING_DEVICE_PATH:
                if ( state != pci || boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                state = ctrlr;
                switch ( DevicePathSubType(devp.DevPath) )
                {
                case MSG_ATAPI_DP:
                    edd_put_string(params->interface_type, "ATAPI");
                    params->interface_path.pci.channel =
                        devp.Atapi->PrimarySecondary;
                    params->device_path.atapi.device = devp.Atapi->SlaveMaster;
                    params->device_path.atapi.lun = devp.Atapi->Lun;
                    break;
                case MSG_SCSI_DP:
                    edd_put_string(params->interface_type, "SCSI");
                    params->device_path.scsi.id = devp.Scsi->Pun;
                    params->device_path.scsi.lun = devp.Scsi->Lun;
                    break;
                case MSG_FIBRECHANNEL_DP:
                    edd_put_string(params->interface_type, "FIBRE");
                    params->device_path.fibre.wwid = devp.FibreChannel->WWN;
                    params->device_path.fibre.lun = devp.FibreChannel->Lun;
                    break;
                case MSG_1394_DP:
                    edd_put_string(params->interface_type, "1394");
                    params->device_path.i1394.eui = devp.F1394->Guid;
                    break;
                case MSG_USB_DP:
                case MSG_USB_CLASS_DP:
                    edd_put_string(params->interface_type, "USB");
                    break;
                case MSG_I2O_DP:
                    edd_put_string(params->interface_type, "I2O");
                    params->device_path.i2o.identity_tag = devp.I2O->Tid;
                    break;
                default:
                    continue;
                }
                info->version = 0x30;
                params->length = sizeof(struct edd_device_params);
                params->key = 0xbedd;
                params->device_path_info_length =
                    sizeof(struct edd_device_params) -
                    offsetof(struct edd_device_params, key);
                for ( p = (const u8 *)&params->key; p < &params->checksum; ++p )
                    params->checksum -= *p;
                break;
            case MEDIA_DEVICE_PATH:
                if ( DevicePathSubType(devp.DevPath) == MEDIA_HARDDRIVE_DP &&
                     devp.HardDrive->MBRType == MBR_TYPE_PCAT &&
                     boot_mbr_signature_nr < EDD_MBR_SIG_MAX )
                {
                    struct mbr_signature *sig = boot_mbr_signature +
                                                boot_mbr_signature_nr;

                    sig->device = 0x80 + boot_edd_info_nr; /* fake */
                    memcpy(&sig->signature, devp.HardDrive->Signature,
                           sizeof(sig->signature));
                    ++boot_mbr_signature_nr;
                }
                break;
            }
        }
    }
    if ( handles )
        efi_bs->FreePool(handles);
    if ( boot_edd_info_nr > EDD_INFO_MAX )
        boot_edd_info_nr = EDD_INFO_MAX;

    /* XXX Collect EDID info. */

    if ( cpuid_eax(0x80000000) > 0x80000000 )
    {
        cpuid_ext_features = cpuid_edx(0x80000001);
        boot_cpu_data.x86_capability[1] = cpuid_ext_features;
    }

    /* Obtain basic table pointers. */
    for ( i = 0; i < efi_num_ct; ++i )
    {
        static EFI_GUID __initdata acpi2_guid = ACPI_20_TABLE_GUID;
        static EFI_GUID __initdata acpi_guid = ACPI_TABLE_GUID;
        static EFI_GUID __initdata mps_guid = MPS_TABLE_GUID;
        static EFI_GUID __initdata smbios_guid = SMBIOS_TABLE_GUID;

        if ( match_guid(&acpi2_guid, &efi_ct[i].VendorGuid) )
	       efi.acpi20 = (long)efi_ct[i].VendorTable;
        if ( match_guid(&acpi_guid, &efi_ct[i].VendorGuid) )
	       efi.acpi = (long)efi_ct[i].VendorTable;
        if ( match_guid(&mps_guid, &efi_ct[i].VendorGuid) )
	       efi.mps = (long)efi_ct[i].VendorTable;
        if ( match_guid(&smbios_guid, &efi_ct[i].VendorGuid) )
	       efi.smbios = (long)efi_ct[i].VendorTable;
    }

    if (efi.smbios != EFI_INVALID_TABLE_ADDR)
        dmi_efi_get_table((void *)(long)efi.smbios);

    /* Collect PCI ROM contents. */
    setup_efi_pci();

    /* Get snapshot of variable store parameters. */
    status = (efi_rs->Hdr.Revision >> 16) >= 2 ?
             efi_rs->QueryVariableInfo(EFI_VARIABLE_NON_VOLATILE |
                                       EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                       EFI_VARIABLE_RUNTIME_ACCESS,
                                       &efi_boot_max_var_store_size,
                                       &efi_boot_remain_var_store_size,
                                       &efi_boot_max_var_size) :
             EFI_INCOMPATIBLE_VERSION;
    if ( EFI_ERROR(status) )
    {
        efi_boot_max_var_store_size = 0;
        efi_boot_remain_var_store_size = 0;
        efi_boot_max_var_size = status;
        PrintStr(L"Warning: Could not query variable store: ");
        DisplayUint(status, 0);
        PrintStr(newline);
    }

    /* Allocate space for trampoline (in first Mb). */
    cfg.addr = 0x100000;
    cfg.size = trampoline_end - trampoline_start;
    status = efi_bs->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                   PFN_UP(cfg.size), &cfg.addr);
    if ( status == EFI_SUCCESS )
        relocate_trampoline(cfg.addr);
    else
    {
        cfg.addr = 0;
        PrintStr(L"Trampoline space cannot be allocated; will try fallback.\r\n");
    }

    /* Initialise L2 identity-map and boot-map page table entries (16MB). */
    for ( i = 0; i < 8; ++i )
    {
        unsigned int slot = (xen_phys_start >> L2_PAGETABLE_SHIFT) + i;
        paddr_t addr = slot << L2_PAGETABLE_SHIFT;

        l2_identmap[slot] = l2e_from_paddr(addr, PAGE_HYPERVISOR|_PAGE_PSE);
        slot &= L2_PAGETABLE_ENTRIES - 1;
        l2_bootmap[slot] = l2e_from_paddr(addr, __PAGE_HYPERVISOR|_PAGE_PSE);
    }
    /* Initialise L3 boot-map page directory entries. */
    l3_bootmap[l3_table_offset(xen_phys_start)] =
        l3e_from_paddr((UINTN)l2_bootmap, __PAGE_HYPERVISOR);
    l3_bootmap[l3_table_offset(xen_phys_start + (8 << L2_PAGETABLE_SHIFT) - 1)] =
        l3e_from_paddr((UINTN)l2_bootmap, __PAGE_HYPERVISOR);

    if ( gop )
    {
        int bpp = 0;

        /* Set graphics mode. */
        if ( gop_mode < gop->Mode->MaxMode && gop_mode != gop->Mode->Mode )
            gop->SetMode(gop, gop_mode);

        /* Get graphics and frame buffer info. */
        status = gop->QueryMode(gop, gop->Mode->Mode, &info_size, &mode_info);
        if ( !EFI_ERROR(status) )
            switch ( mode_info->PixelFormat )
            {
            case PixelRedGreenBlueReserved8BitPerColor:
                vga_console_info.u.vesa_lfb.red_pos = 0;
                vga_console_info.u.vesa_lfb.red_size = 8;
                vga_console_info.u.vesa_lfb.green_pos = 8;
                vga_console_info.u.vesa_lfb.green_size = 8;
                vga_console_info.u.vesa_lfb.blue_pos = 16;
                vga_console_info.u.vesa_lfb.blue_size = 8;
                vga_console_info.u.vesa_lfb.rsvd_pos = 24;
                vga_console_info.u.vesa_lfb.rsvd_size = 8;
                bpp = 32;
                break;
            case PixelBlueGreenRedReserved8BitPerColor:
                vga_console_info.u.vesa_lfb.red_pos = 16;
                vga_console_info.u.vesa_lfb.red_size = 8;
                vga_console_info.u.vesa_lfb.green_pos = 8;
                vga_console_info.u.vesa_lfb.green_size = 8;
                vga_console_info.u.vesa_lfb.blue_pos = 0;
                vga_console_info.u.vesa_lfb.blue_size = 8;
                vga_console_info.u.vesa_lfb.rsvd_pos = 24;
                vga_console_info.u.vesa_lfb.rsvd_size = 8;
                bpp = 32;
                break;
            case PixelBitMask:
                bpp = set_color(mode_info->PixelInformation.RedMask, bpp,
                                &vga_console_info.u.vesa_lfb.red_pos,
                                &vga_console_info.u.vesa_lfb.red_size);
                bpp = set_color(mode_info->PixelInformation.GreenMask, bpp,
                                &vga_console_info.u.vesa_lfb.green_pos,
                                &vga_console_info.u.vesa_lfb.green_size);
                bpp = set_color(mode_info->PixelInformation.BlueMask, bpp,
                                &vga_console_info.u.vesa_lfb.blue_pos,
                                &vga_console_info.u.vesa_lfb.blue_size);
                bpp = set_color(mode_info->PixelInformation.ReservedMask, bpp,
                                &vga_console_info.u.vesa_lfb.rsvd_pos,
                                &vga_console_info.u.vesa_lfb.rsvd_size);
                if ( bpp > 0 )
                    break;
                /* fall through */
            default:
                PrintErr(L"Current graphics mode is unsupported!\r\n");
                status = EFI_UNSUPPORTED;
                break;
            }
        if ( !EFI_ERROR(status) )
        {
            vga_console_info.video_type = XEN_VGATYPE_EFI_LFB;
            vga_console_info.u.vesa_lfb.gbl_caps = 2; /* possibly non-VGA */
            vga_console_info.u.vesa_lfb.width =
                mode_info->HorizontalResolution;
            vga_console_info.u.vesa_lfb.height = mode_info->VerticalResolution;
            vga_console_info.u.vesa_lfb.bits_per_pixel = bpp;
            vga_console_info.u.vesa_lfb.bytes_per_line =
                (mode_info->PixelsPerScanLine * bpp + 7) >> 3;
            vga_console_info.u.vesa_lfb.lfb_base = gop->Mode->FrameBufferBase;
            vga_console_info.u.vesa_lfb.lfb_size =
                (gop->Mode->FrameBufferSize + 0xffff) >> 16;
        }
    }

    efi_bs->GetMemoryMap(&efi_memmap_size, NULL, &map_key,
                         &efi_mdesc_size, &mdesc_ver);
    mbi.mem_upper -= efi_memmap_size;
    mbi.mem_upper &= -__alignof__(EFI_MEMORY_DESCRIPTOR);
    if ( mbi.mem_upper < xen_phys_start )
        blexit(L"Out of static memory");
    efi_memmap = (void *)(long)mbi.mem_upper;
    status = efi_bs->GetMemoryMap(&efi_memmap_size, efi_memmap, &map_key,
                                  &efi_mdesc_size, &mdesc_ver);
    if ( EFI_ERROR(status) )
        PrintErrMesgExit(L"Cannot obtain memory map", status);

    /* Populate E820 table and check trampoline area availability. */
    e = e820map - 1;
    for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
    {
        EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;
        u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;
        u32 type;

        switch ( desc->Type )
        {
        default:
            type = E820_RESERVED;
            break;
        case EfiConventionalMemory:
        case EfiBootServicesCode:
        case EfiBootServicesData:
            if ( !trampoline_phys && desc->PhysicalStart + len <= 0x100000 &&
                 len >= cfg.size && desc->PhysicalStart + len > cfg.addr )
                cfg.addr = (desc->PhysicalStart + len - cfg.size) & PAGE_MASK;
            /* fall through */
        case EfiLoaderCode:
        case EfiLoaderData:
            if ( desc->Attribute & EFI_MEMORY_WB )
                type = E820_RAM;
            else
        case EfiUnusableMemory:
                type = E820_UNUSABLE;
            break;
        case EfiACPIReclaimMemory:
            type = E820_ACPI;
            break;
        case EfiACPIMemoryNVS:
            type = E820_NVS;
            break;
        }
        if ( e820nr && type == e->type &&
             desc->PhysicalStart == e->addr + e->size )
            e->size += len;
        else if ( !len || e820nr >= E820MAX )
            continue;
        else
        {
            ++e;
            e->addr = desc->PhysicalStart;
            e->size = len;
            e->type = type;
            ++e820nr;
        }
    }
    if ( !trampoline_phys )
    {
        if ( !cfg.addr )
            blexit(L"No memory for trampoline");
        relocate_trampoline(cfg.addr);
    }

    status = efi_bs->ExitBootServices(ImageHandle, map_key);
    if ( EFI_ERROR(status) )
        PrintErrMesgExit(L"Cannot exit boot services", status);

    /* Adjust pointers into EFI. */
    efi_ct = (void *)efi_ct + DIRECTMAP_VIRT_START;
#ifdef USE_SET_VIRTUAL_ADDRESS_MAP
    efi_rs = (void *)efi_rs + DIRECTMAP_VIRT_START;
#endif
    efi_memmap = (void *)efi_memmap + DIRECTMAP_VIRT_START;
    efi_fw_vendor = (void *)efi_fw_vendor + DIRECTMAP_VIRT_START;

    relocate_image(__XEN_VIRT_START - xen_phys_start);
    memcpy((void *)trampoline_phys, trampoline_start, cfg.size);

    /* Set system registers and transfer control. */
    asm volatile("pushq $0\n\tpopfq");
    rdmsrl(MSR_EFER, efer);
    efer |= EFER_SCE;
    if ( cpuid_ext_features & (1 << (X86_FEATURE_NX & 0x1f)) )
        efer |= EFER_NX;
    wrmsrl(MSR_EFER, efer);
    write_cr0(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP |
              X86_CR0_AM | X86_CR0_PG);
    asm volatile ( "mov    %[cr4], %%cr4\n\t"
                   "mov    %[cr3], %%cr3\n\t"
                   "movabs $__start_xen, %[rip]\n\t"
                   "lgdt   gdt_descr(%%rip)\n\t"
                   "mov    stack_start(%%rip), %%rsp\n\t"
                   "mov    %[ds], %%ss\n\t"
                   "mov    %[ds], %%ds\n\t"
                   "mov    %[ds], %%es\n\t"
                   "mov    %[ds], %%fs\n\t"
                   "mov    %[ds], %%gs\n\t"
                   "movl   %[cs], 8(%%rsp)\n\t"
                   "mov    %[rip], (%%rsp)\n\t"
                   "lretq  %[stkoff]-16"
                   : [rip] "=&r" (efer/* any dead 64-bit variable */)
                   : [cr3] "r" (idle_pg_table),
                     [cr4] "r" (mmu_cr4_features),
                     [cs] "ir" (__HYPERVISOR_CS),
                     [ds] "r" (__HYPERVISOR_DS),
                     [stkoff] "i" (STACK_SIZE - sizeof(struct cpu_info)),
                     "D" (&mbi)
                   : "memory" );
    for( ; ; ); /* not reached */
}

#ifndef USE_SET_VIRTUAL_ADDRESS_MAP
static __init void copy_mapping(unsigned long mfn, unsigned long end,
                                bool_t (*is_valid)(unsigned long smfn,
                                                   unsigned long emfn))
{
    unsigned long next;

    for ( ; mfn < end; mfn = next )
    {
        l4_pgentry_t l4e = efi_l4_pgtable[l4_table_offset(mfn << PAGE_SHIFT)];
        l3_pgentry_t *l3src, *l3dst;
        unsigned long va = (unsigned long)mfn_to_virt(mfn);

        next = mfn + (1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT));
        if ( !is_valid(mfn, min(next, end)) )
            continue;
        if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        {
            l3dst = alloc_xen_pagetable();
            BUG_ON(!l3dst);
            clear_page(l3dst);
            efi_l4_pgtable[l4_table_offset(mfn << PAGE_SHIFT)] =
                l4e_from_paddr(virt_to_maddr(l3dst), __PAGE_HYPERVISOR);
        }
        else
            l3dst = l4e_to_l3e(l4e);
        l3src = l4e_to_l3e(idle_pg_table[l4_table_offset(va)]);
        l3dst[l3_table_offset(mfn << PAGE_SHIFT)] = l3src[l3_table_offset(va)];
    }
}

static bool_t __init ram_range_valid(unsigned long smfn, unsigned long emfn)
{
    unsigned long sz = pfn_to_pdx(emfn - 1) / PDX_GROUP_COUNT + 1;

    return !(smfn & pfn_hole_mask) &&
           find_next_bit(pdx_group_valid, sz,
                         pfn_to_pdx(smfn) / PDX_GROUP_COUNT) < sz;
}

static bool_t __init rt_range_valid(unsigned long smfn, unsigned long emfn)
{
    return 1;
}
#endif

#define INVALID_VIRTUAL_ADDRESS (0xBAAADUL << \
                                 (EFI_PAGE_SHIFT + BITS_PER_LONG - 32))

void __init efi_init_memory(void)
{
    unsigned int i;
#ifndef USE_SET_VIRTUAL_ADDRESS_MAP
    struct rt_extra {
        struct rt_extra *next;
        unsigned long smfn, emfn;
        unsigned int prot;
    } *extra, *extra_head = NULL;
#endif

    printk(XENLOG_INFO "EFI memory map:\n");
    for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
    {
        EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;
        u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;
        unsigned long smfn, emfn;
        unsigned int prot = PAGE_HYPERVISOR;

        printk(XENLOG_INFO " %013" PRIx64 "-%013" PRIx64
                           " type=%u attr=%016" PRIx64 "\n",
               desc->PhysicalStart, desc->PhysicalStart + len - 1,
               desc->Type, desc->Attribute);

        if ( !(desc->Attribute & EFI_MEMORY_RUNTIME) )
            continue;

        desc->VirtualStart = INVALID_VIRTUAL_ADDRESS;

        smfn = PFN_DOWN(desc->PhysicalStart);
        emfn = PFN_UP(desc->PhysicalStart + len);

        if ( desc->Attribute & EFI_MEMORY_WB )
            /* nothing */;
        else if ( desc->Attribute & EFI_MEMORY_WT )
            prot |= _PAGE_PWT | MAP_SMALL_PAGES;
        else if ( desc->Attribute & EFI_MEMORY_WC )
            prot |= _PAGE_PAT | MAP_SMALL_PAGES;
        else if ( desc->Attribute & (EFI_MEMORY_UC | EFI_MEMORY_UCE) )
            prot |= _PAGE_PWT | _PAGE_PCD | MAP_SMALL_PAGES;
        else
        {
            printk(XENLOG_ERR "Unknown cachability for MFNs %#lx-%#lx\n",
                   smfn, emfn - 1);
            continue;
        }

        if ( desc->Attribute & EFI_MEMORY_WP )
            prot &= _PAGE_RW;
        if ( desc->Attribute & EFI_MEMORY_XP )
            prot |= _PAGE_NX_BIT;

        if ( pfn_to_pdx(emfn - 1) < (DIRECTMAP_SIZE >> PAGE_SHIFT) &&
             !(smfn & pfn_hole_mask) &&
             !((smfn ^ (emfn - 1)) & ~pfn_pdx_bottom_mask) )
        {
            if ( (unsigned long)mfn_to_virt(emfn - 1) >= HYPERVISOR_VIRT_END )
                prot &= ~_PAGE_GLOBAL;
            if ( map_pages_to_xen((unsigned long)mfn_to_virt(smfn),
                                  smfn, emfn - smfn, prot) == 0 )
                desc->VirtualStart =
                    (unsigned long)maddr_to_virt(desc->PhysicalStart);
            else
                printk(XENLOG_ERR "Could not map MFNs %#lx-%#lx\n",
                       smfn, emfn - 1);
        }
#ifndef USE_SET_VIRTUAL_ADDRESS_MAP
        else if ( !((desc->PhysicalStart + len - 1) >> (VADDR_BITS - 1)) &&
                  (extra = xmalloc(struct rt_extra)) != NULL )
        {
            extra->smfn = smfn;
            extra->emfn = emfn;
            extra->prot = prot & ~_PAGE_GLOBAL;
            extra->next = extra_head;
            extra_head = extra;
            desc->VirtualStart = desc->PhysicalStart;
        }
#endif
        else
        {
#ifdef USE_SET_VIRTUAL_ADDRESS_MAP
            /* XXX allocate e.g. down from FIXADDR_START */
#endif
            printk(XENLOG_ERR "No mapping for MFNs %#lx-%#lx\n",
                   smfn, emfn - 1);
        }
    }

#ifdef USE_SET_VIRTUAL_ADDRESS_MAP
    efi_rs->SetVirtualAddressMap(efi_memmap_size, efi_mdesc_size,
                                 mdesc_ver, efi_memmap);
#else
    /* Set up 1:1 page tables to do runtime calls in "physical" mode. */
    efi_l4_pgtable = alloc_xen_pagetable();
    BUG_ON(!efi_l4_pgtable);
    clear_page(efi_l4_pgtable);

    copy_mapping(0, max_page, ram_range_valid);

    /* Insert non-RAM runtime mappings inside the direct map. */
    for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
    {
        const EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;

        if ( (desc->Attribute & EFI_MEMORY_RUNTIME) &&
             desc->VirtualStart != INVALID_VIRTUAL_ADDRESS &&
             desc->VirtualStart != desc->PhysicalStart )
            copy_mapping(PFN_DOWN(desc->PhysicalStart),
                         PFN_UP(desc->PhysicalStart +
                                (desc->NumberOfPages << EFI_PAGE_SHIFT)),
                         rt_range_valid);
    }

    /* Insert non-RAM runtime mappings outside of the direct map. */
    while ( (extra = extra_head) != NULL )
    {
        unsigned long addr = extra->smfn << PAGE_SHIFT;
        l4_pgentry_t l4e = efi_l4_pgtable[l4_table_offset(addr)];
        l3_pgentry_t *pl3e;
        l2_pgentry_t *pl2e;
        l1_pgentry_t *l1t;

        if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        {
            pl3e = alloc_xen_pagetable();
            BUG_ON(!pl3e);
            clear_page(pl3e);
            efi_l4_pgtable[l4_table_offset(addr)] =
                l4e_from_paddr(virt_to_maddr(pl3e), __PAGE_HYPERVISOR);
        }
        else
            pl3e = l4e_to_l3e(l4e);
        pl3e += l3_table_offset(addr);
        if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
        {
            pl2e = alloc_xen_pagetable();
            BUG_ON(!pl2e);
            clear_page(pl2e);
            *pl3e = l3e_from_paddr(virt_to_maddr(pl2e), __PAGE_HYPERVISOR);
        }
        else
        {
            BUG_ON(l3e_get_flags(*pl3e) & _PAGE_PSE);
            pl2e = l3e_to_l2e(*pl3e);
        }
        pl2e += l2_table_offset(addr);
        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
        {
            l1t = alloc_xen_pagetable();
            BUG_ON(!l1t);
            clear_page(l1t);
            *pl2e = l2e_from_paddr(virt_to_maddr(l1t), __PAGE_HYPERVISOR);
        }
        else
        {
            BUG_ON(l2e_get_flags(*pl2e) & _PAGE_PSE);
            l1t = l2e_to_l1e(*pl2e);
        }
        for ( i = l1_table_offset(addr);
              i < L1_PAGETABLE_ENTRIES && extra->smfn < extra->emfn;
              ++i, ++extra->smfn )
            l1t[i] = l1e_from_pfn(extra->smfn, extra->prot);

        if ( extra->smfn == extra->emfn )
        {
            extra_head = extra->next;
            xfree(extra);
        }
    }

    /* Insert Xen mappings. */
    for ( i = l4_table_offset(HYPERVISOR_VIRT_START);
          i < l4_table_offset(DIRECTMAP_VIRT_END); ++i )
        efi_l4_pgtable[i] = idle_pg_table[i];
#endif
}
