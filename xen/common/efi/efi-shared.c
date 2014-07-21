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


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
