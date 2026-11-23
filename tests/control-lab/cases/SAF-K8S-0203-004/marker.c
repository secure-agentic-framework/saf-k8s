/* UEFI marker application for a disposable QEMU firmware test. */
typedef unsigned long long UInt64;
typedef unsigned int UInt32;
typedef unsigned short UInt16;
typedef unsigned char UInt8;
typedef UInt64 Status;
typedef UInt16 WideChar;

typedef struct {
    UInt64 signature;
    UInt32 revision;
    UInt32 header_size;
    UInt32 crc32;
    UInt32 reserved;
} TableHeader;

typedef struct {
    UInt32 low;
    UInt16 middle;
    UInt16 high;
    UInt8 tail[8];
} Guid;

typedef Status (*GetVariable)(const WideChar *, const Guid *, UInt32 *, UInt64 *, void *);
typedef void (*ResetSystem)(UInt32, Status, UInt64, const void *);

typedef struct {
    TableHeader header;
    void *earlier_functions[6];
    GetVariable get_variable;
    void *later_functions[3];
    ResetSystem reset_system;
} RuntimeServices;

typedef struct OutputProtocol OutputProtocol;
struct OutputProtocol {
    void *reset;
    Status (*output_string)(OutputProtocol *, const WideChar *);
};

typedef struct {
    TableHeader header;
    void *firmware_vendor;
    UInt32 firmware_revision;
    void *console_in_handle;
    void *console_in;
    void *console_out_handle;
    OutputProtocol *console_out;
    void *stderr_handle;
    void *stderr_protocol;
    RuntimeServices *runtime;
} SystemTable;

Status efi_main(void *image, SystemTable *system) {
    (void)image;
    const Guid globals = {0x8be4df61, 0x93ca, 0x11d2, {0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}};
    UInt8 secure_boot = 0;
    UInt64 size = sizeof(secure_boot);
    Status read = system->runtime->get_variable(L"SecureBoot", &globals, 0, &size, &secure_boot);
    const WideChar *marker = L"SAF-BOOT-MARKER: unknown\r\n";
    if (read == 0 && size == 1) {
        marker = secure_boot == 1 ? L"SAF-BOOT-MARKER: enforcing\r\n" : L"SAF-BOOT-MARKER: disabled\r\n";
    }
    system->console_out->output_string(system->console_out, marker);
    system->runtime->reset_system(2, 0, 0, 0);
    return 0;
}
