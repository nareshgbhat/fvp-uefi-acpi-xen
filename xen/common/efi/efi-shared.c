/* EFI code shared between architectures. */

#include <asm/efibind.h>
#include <efi/efidef.h>
#include <efi/efierr.h>
#include <efi/eficon.h>
#include <efi/efidevp.h>
#include <efi/eficapsule.h>
#include <efi/efiapi.h>
#include <xen/efi.h>
#include <xen/spinlock.h>
#include <asm/page.h>
#include <efi/efiprot.h>
#include <efi/efipciio.h>
#include <efi/efi-shared.h>
#include <public/xen.h>
#include <efi/efi-shared.h>
#include <xen/compile.h>
#include <xen/ctype.h>
#include <xen/init.h>
#include <asm/processor.h>
#include <xen/keyhandler.h>
#include <xen/pfn.h>
#if EFI_PAGE_SIZE != PAGE_SIZE
# error Cannot use xen/pfn.h here!
#endif


SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdOut;
SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdErr;
EFI_BOOT_SERVICES *__initdata efi_bs;


CHAR16 __initdata newline[] = L"\r\n";

CHAR16 *__init FormatDec(UINT64 Val, CHAR16 *Buffer)
{
    if ( Val >= 10 )
        Buffer = FormatDec(Val / 10, Buffer);
    *Buffer = (CHAR16)(L'0' + Val % 10);
    return Buffer + 1;
}

CHAR16 *__init FormatHex(UINT64 Val, UINTN Width, CHAR16 *Buffer)
{
    if ( Width > 1 || Val >= 0x10 )
        Buffer = FormatHex(Val >> 4, Width ? Width - 1 : 0, Buffer);
    *Buffer = (CHAR16)((Val &= 0xf) < 10 ? L'0' + Val : L'a' + Val - 10);
    return Buffer + 1;
}


void __init DisplayUint(UINT64 Val, INTN Width)
{
    CHAR16 PrintString[32], *end;

    if ( Width < 0 )
        end = FormatDec(Val, PrintString);
    else
    {
        PrintStr(L"0x");
        end = FormatHex(Val, Width, PrintString);
    }
    *end = 0;
    PrintStr(PrintString);
}

CHAR16 *__init wstrcpy(CHAR16 *d, const CHAR16 *s)
{
    CHAR16 *r = d;

    while ( (*d++ = *s++) != 0 )
        ;
    return r;
}

int __init wstrcmp(const CHAR16 *s1, const CHAR16 *s2)
{
    while ( *s1 && *s1 == *s2 )
    {
        ++s1;
        ++s2;
    }
    return *s1 - *s2;
}

int __init wstrncmp(const CHAR16 *s1, const CHAR16 *s2, UINTN n)
{
    while ( n && *s1 && *s1 == *s2 )
    {
        --n;
        ++s1;
        ++s2;
    }
    return n ? *s1 - *s2 : 0;
}

CHAR16 *__init s2w(union string *str)
{
    const char *s = str->s;
    CHAR16 *w;
    void *ptr;

    if ( efi_bs->AllocatePool(EfiLoaderData, (strlen(s) + 1) * sizeof(*w),
                              &ptr) != EFI_SUCCESS )
        return NULL;

    w = str->w = ptr;
    do {
        *w = *s++;
    } while ( *w++ );

    return str->w;
}

char *__init w2s(const union string *str)
{
    const CHAR16 *w = str->w;
    char *s = str->s;

    do {
        if ( *w > 0x007f )
            return NULL;
        *s = *w++;
    } while ( *s++ );

    return str->s;
}

bool_t __init match_guid(const EFI_GUID *guid1, const EFI_GUID *guid2)
{
    return guid1->Data1 == guid2->Data1 &&
           guid1->Data2 == guid2->Data2 &&
           guid1->Data3 == guid2->Data3 &&
           !memcmp(guid1->Data4, guid2->Data4, sizeof(guid1->Data4));
}


/* generic routine for printing error messages */
void __init PrintErrMesg(const CHAR16 *mesg, EFI_STATUS ErrCode)
{
    StdOut = StdErr;
    PrintErr((CHAR16 *)mesg);
    PrintErr(L": ");

    switch (ErrCode)
    {
    case EFI_NOT_FOUND:
        mesg = L"Not found";
        break;
    case EFI_NO_MEDIA:
        mesg = L"The device has no media";
        break;
    case EFI_MEDIA_CHANGED:
        mesg = L"Media changed";
        break;
    case EFI_DEVICE_ERROR:
        mesg = L"Device error";
        break;
    case EFI_VOLUME_CORRUPTED:
        mesg = L"Volume corrupted";
        break;
    case EFI_ACCESS_DENIED:
        mesg = L"Access denied";
        break;
    case EFI_OUT_OF_RESOURCES:
        mesg = L"Out of resources";
        break;
    case EFI_VOLUME_FULL:
        mesg = L"Volume is full";
        break;
    case EFI_SECURITY_VIOLATION:
        mesg = L"Security violation";
        break;
    case EFI_CRC_ERROR:
        mesg = L"CRC error";
        break;
    case EFI_COMPROMISED_DATA:
        mesg = L"Compromised data";
        break;
    default:
        PrintErr(L"ErrCode: ");
        DisplayUint(ErrCode, 0);
        mesg = NULL;
        break;
    }
}


EFI_FILE_HANDLE __init get_parent_handle(EFI_LOADED_IMAGE *loaded_image,
                                         CHAR16 **leaf)
{
    static EFI_GUID __initdata fs_protocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
    EFI_FILE_HANDLE dir_handle;
    EFI_DEVICE_PATH *dp;
    CHAR16 *pathend, *ptr;
    EFI_STATUS ret;

    do {
        EFI_FILE_IO_INTERFACE *fio;

        /* Get the file system interface. */
        ret = efi_bs->HandleProtocol(loaded_image->DeviceHandle,
                                     &fs_protocol, (void **)&fio);
        if ( EFI_ERROR(ret) )
        {
            PrintErrMesg(L"Couldn't obtain the File System Protocol Interface",
                         ret);
            return NULL;
        }
        ret = fio->OpenVolume(fio, &dir_handle);
    } while ( ret == EFI_MEDIA_CHANGED );
    if ( ret != EFI_SUCCESS )
    {
        PrintErrMesg(L"OpenVolume failure", ret);
        return NULL;
    }

#define buffer ((CHAR16 *)keyhandler_scratch)
#define BUFFERSIZE sizeof(keyhandler_scratch)
    for ( dp = loaded_image->FilePath, *buffer = 0;
          DevicePathType(dp) != END_DEVICE_PATH_TYPE;
          dp = (void *)dp + DevicePathNodeLength(dp) )
    {
        FILEPATH_DEVICE_PATH *fp;

        if ( DevicePathType(dp) != MEDIA_DEVICE_PATH ||
             DevicePathSubType(dp) != MEDIA_FILEPATH_DP )
        {
            PrintErr(L"Unsupported device path component");
            return NULL;
        }

        if ( *buffer )
        {
            EFI_FILE_HANDLE new_handle;

            ret = dir_handle->Open(dir_handle, &new_handle, buffer,
                                   EFI_FILE_MODE_READ, 0);
            if ( ret != EFI_SUCCESS )
            {
                PrintErr(L"Open failed for ");
                PrintErrMesg(buffer, ret);
                return NULL;
            }
            dir_handle->Close(dir_handle);
            dir_handle = new_handle;
        }
        fp = (void *)dp;
        if ( BUFFERSIZE < DevicePathNodeLength(dp) -
                          sizeof(*dp) + sizeof(*buffer) )
        {
            PrintErr(L"Increase BUFFERSIZE");
            return NULL;
        }
        memcpy(buffer, fp->PathName, DevicePathNodeLength(dp) - sizeof(*dp));
        buffer[(DevicePathNodeLength(dp) - sizeof(*dp)) / sizeof(*buffer)] = 0;
    }
    for ( ptr = buffer, pathend = NULL; *ptr; ++ptr )
        if ( *ptr == L'\\' )
            pathend = ptr;
    if ( pathend )
    {
        *pathend = 0;
        *leaf = pathend + 1;
        if ( *buffer )
        {
            EFI_FILE_HANDLE new_handle;

            ret = dir_handle->Open(dir_handle, &new_handle, buffer,
                                   EFI_FILE_MODE_READ, 0);
            if ( ret != EFI_SUCCESS ) {
                PrintErr(L"Open failed for ");
                PrintErrMesg(buffer, ret);
                return NULL;
            }
            dir_handle->Close(dir_handle);
            dir_handle = new_handle;
        }
    }
    else
        *leaf = buffer;
#undef BUFFERSIZE
#undef buffer

    return dir_handle;
}

CHAR16 *__init point_tail(CHAR16 *fn)
{
    CHAR16 *tail = NULL;

    for ( ; ; ++fn )
        switch ( *fn )
        {
        case 0:
            return tail;
        case L'.':
        case L'-':
        case L'_':
            tail = fn;
            break;
        }
}

bool_t __init read_file(EFI_FILE_HANDLE dir_handle, CHAR16 *name,
                               struct file *file, EFI_PHYSICAL_ADDRESS max_addr)
{
    EFI_FILE_HANDLE FileHandle = NULL;
    UINT64 size;
    EFI_STATUS ret;
    CHAR16 *what = NULL;

    if ( !name )
    {
        PrintErrMesg(L"No Filename", EFI_OUT_OF_RESOURCES);
        return 0;
    }

    ret = dir_handle->Open(dir_handle, &FileHandle, name,
                           EFI_FILE_MODE_READ, 0);

    if ( EFI_ERROR(ret) )
        what = L"Open";
    else
        ret = FileHandle->SetPosition(FileHandle, -1);
    if ( EFI_ERROR(ret) )
        what = what ?: L"Seek";
    else
        ret = FileHandle->GetPosition(FileHandle, &size);
    if ( EFI_ERROR(ret) )
        what = what ?: L"Get size";
    else
        ret = FileHandle->SetPosition(FileHandle, 0);
    if ( EFI_ERROR(ret) )
        what = what ?: L"Seek";
    else
    {
        file->addr = max_addr;
        ret = efi_bs->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                    PFN_UP(size), &file->addr);
    }
    if ( EFI_ERROR(ret) )
    {
        file->addr = 0;
        what = what ?: L"Allocation";
    }
    else
    {

        file->size = size;
        ret = FileHandle->Read(FileHandle, &file->size, file->ptr);
        if ( !EFI_ERROR(ret) && file->size != size )
            ret = EFI_ABORTED;
        if ( EFI_ERROR(ret) )
        {
            what = what ?: L"Read";
            efi_bs->FreePages(file->addr, PFN_UP(file->size));
            file->addr = 0;
        }
    }

    if ( FileHandle )
        FileHandle->Close(FileHandle);

    if ( what )
    {
        PrintErrMesg(what, ret);
        PrintErr(L"Unable to load file");
        return 0;
    }
    else
    {
        PrintStr(name);
        PrintStr(L": ");
        DisplayUint(file->addr, 2 * sizeof(file->addr));
        PrintStr(L"-");
        DisplayUint(file->addr + file->size, 2 * sizeof(file->addr));
        PrintStr(newline);
        return 1;
    }

}

void __init pre_parse(const struct file *cfg)
{
    char *ptr = cfg->ptr, *end = ptr + cfg->size;
    bool_t start = 1, comment = 0;

    for ( ; ptr < end; ++ptr )
    {
        if ( iscntrl(*ptr) )
        {
            comment = 0;
            start = 1;
            *ptr = 0;
        }
        else if ( comment || (start && isspace(*ptr)) )
            *ptr = 0;
        else if ( *ptr == '#' || (start && *ptr == ';') )
        {
            comment = 1;
            *ptr = 0;
        }
        else
            start = 0;
    }
    if ( cfg->size && end[-1] )
         PrintStr(L"No newline at end of config file,"
                   " last line will be ignored.\r\n");
}

char *__init get_value(const struct file *cfg, const char *section,
                       const char *item)
{
    char *ptr = cfg->ptr, *end = ptr + cfg->size;
    size_t slen = section ? strlen(section) : 0, ilen = strlen(item);
    bool_t match = !slen;

    for ( ; ptr < end; ++ptr )
    {
        switch ( *ptr )
        {
        case 0:
            continue;
        case '[':
            if ( !slen )
                break;
            if ( match )
                return NULL;
            match = strncmp(++ptr, section, slen) == 0 && ptr[slen] == ']';
            break;
        default:
            if ( match && strncmp(ptr, item, ilen) == 0 && ptr[ilen] == '=' )
            {
                ptr += ilen + 1;
                /* strip off any leading spaces */
                while ( *ptr && isspace(*ptr) )
                    ptr++;
                return ptr;
            }
            break;
        }
        ptr += strlen(ptr);
    }
    return NULL;
}

/* Truncate string at first space, and return pointer
 * to remainder of string.
 */
char * __init truncate_string(char *s)
{
    while ( *s && !isspace(*s) )
        ++s;
    if (*s)
    {
        *s = 0;
        return(s + 1);
    }
    return(NULL);
}

unsigned int __init get_argv(unsigned int argc, CHAR16 **argv, CHAR16 *cmdline,
                             UINTN cmdsize, CHAR16 **cmdline_remain)
{
    CHAR16 *ptr = (CHAR16 *)(argv + argc + 1), *prev = NULL;
    bool_t prev_sep = TRUE;

    for ( ; cmdsize > sizeof(*cmdline) && *cmdline;
            cmdsize -= sizeof(*cmdline), ++cmdline )
    {
        bool_t cur_sep = *cmdline == L' ' || *cmdline == L'\t';

        if ( !prev_sep )
        {
            if ( cur_sep )
                ++ptr;
            else if ( argv )
            {
                *ptr = *cmdline;
                *++ptr = 0;
            }
        }
        else if ( !cur_sep )
        {
            if ( !argv )
                ++argc;
            else if ( prev && wstrcmp(prev, L"--") == 0 )
            {
                --argv;
                if (**cmdline_remain)
                    *cmdline_remain = cmdline;
                break;
            }
            else
            {
                *argv++ = prev = ptr;
                *ptr = *cmdline;
                *++ptr = 0;
            }
        }
        prev_sep = cur_sep;
    }
    if ( argv )
        *argv = NULL;
    return argc;
}

bool_t __init read_config_file(EFI_FILE_HANDLE *cfg_dir_handle,
                             struct file *cfg, CHAR16 *cfg_file_name,
                             union string *section,
                             CHAR16 *xen_file_name)
{
    /*
     * This allocation is internal to the EFI stub, so any address is
     * fine.
     */
    EFI_PHYSICAL_ADDRESS max = ~0;

    /* Read and parse the config file. */
    if ( !cfg_file_name )
    {
        CHAR16 *tail;

        while ( (tail = point_tail(xen_file_name)) != NULL )
        {
            wstrcpy(tail, L".cfg");
            if ( read_file(*cfg_dir_handle, xen_file_name, cfg, max) )
                break;
            *tail = 0;
        }
        if ( !tail )
            return 0;
        PrintStr(L"Using configuration file '");
        PrintStr(xen_file_name);
        PrintStr(L"'\r\n");
    }
    else if ( !read_file(*cfg_dir_handle, cfg_file_name, cfg, max) )
        return 0;
    pre_parse(cfg);

    if ( section->w )
        w2s(section);
    else
        section->s = get_value(cfg, "global", "default");


    for ( ; ; )
    {
        union string dom0_kernel_name;
        dom0_kernel_name.s = get_value(cfg, section->s, "kernel");
        if ( dom0_kernel_name.s )
            break;
        dom0_kernel_name.s = get_value(cfg, "global", "chain");
        if ( !dom0_kernel_name.s )
            break;
        efi_bs->FreePages(cfg->addr, PFN_UP(cfg->size));
        cfg->addr = 0;
        if ( !read_file(*cfg_dir_handle, s2w(&dom0_kernel_name), cfg, max) )
        {
            PrintStr(L"Chained configuration file '");
            PrintStr(dom0_kernel_name.w);
            efi_bs->FreePool(dom0_kernel_name.w);
            PrintStr(L"'not found.");
            return 0;
        }
        pre_parse(cfg);
        efi_bs->FreePool(dom0_kernel_name.w);
    }
    return 1;
}
bool_t __init handle_cmdline(EFI_LOADED_IMAGE *loaded_image,
                           CHAR16 **cfg_file_name, bool_t *base_video,
                           CHAR16 **image_name, CHAR16 **section_name,
                           CHAR16 **cmdline_remain)
{

    unsigned int i, argc;
    CHAR16 **argv;


    if ( !cfg_file_name || !base_video || !image_name )
    {
        PrintStr(L"Invalid args to handle_cmdline\r\n");
        return 0;
    }

    argc = get_argv(0, NULL, loaded_image->LoadOptions,
                    loaded_image->LoadOptionsSize, NULL);
    if ( argc > 0 &&
         efi_bs->AllocatePool(EfiLoaderData,
                              (argc + 1) * sizeof(*argv) +
                                  loaded_image->LoadOptionsSize,
                              (void **)&argv) == EFI_SUCCESS )
        get_argv(argc, argv, loaded_image->LoadOptions,
                 loaded_image->LoadOptionsSize, cmdline_remain);
    else
        argc = 0;

    for ( i = 1; i < argc; ++i )
    {
        CHAR16 *ptr = argv[i];

        if ( !ptr )
            break;
        if ( *ptr == L'/' || *ptr == L'-' )
        {
            if ( wstrcmp(ptr + 1, L"basevideo") == 0 )
                *base_video = 1;
            else if ( wstrncmp(ptr + 1, L"cfg=", 4) == 0 )
                *cfg_file_name = ptr + 5;
            else if ( i + 1 < argc && wstrcmp(ptr + 1, L"cfg") == 0 )
                *cfg_file_name = argv[++i];
            else if ( wstrcmp(ptr + 1, L"help") == 0 ||
                      (ptr[1] == L'?' && !ptr[2]) )
            {
                PrintStr(L"Xen EFI Loader options:\r\n");
                PrintStr(L"-basevideo   retain current video mode\r\n");
                PrintStr(L"-cfg=<file>  specify configuration file\r\n");
                PrintStr(L"-help, -?    display this help\r\n");
                return 0;
            }
            else
            {
                PrintStr(L"WARNING: Unknown command line option '");
                PrintStr(ptr);
                PrintStr(L"' ignored\r\n");
            }
        }
        else
            *section_name = ptr;
    }

    if ( argc )
        *image_name = *argv;

    return 1;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
