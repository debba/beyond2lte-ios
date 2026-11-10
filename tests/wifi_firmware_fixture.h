/* Synthetic staging fixture only. No vendor firmware is included in tests. */
#include <stddef.h>
typedef void *DTEntry;
typedef struct { uint64_t physBase, topOfKernelData; } boot_args;
static _Alignas(4096) uint8_t firmware_fixture[1297036];
static boot_args firmware_args;
static struct { void *bootArgs; } PE_state = { &firmware_args };
static unsigned firmware_fault;
#define kSuccess 0
static inline void firmware_fixture_setup(void) {
    firmware_fault=0;
    firmware_args.physBase=(uintptr_t)firmware_fixture;
    firmware_args.topOfKernelData=firmware_args.physBase+sizeof(firmware_fixture);
    for(unsigned i=0;i<sizeof(firmware_fixture);i++)firmware_fixture[i]=(uint8_t)(i*13u+7u);
}
static int SecureDTLookupEntry(const void *start,const char *name,DTEntry *dt) {
    assert(!start&&!strcmp(name,"/chosen"));*dt=NULL;return firmware_fault==1 ? -1:0;
}
static int SecureDTGetProperty(DTEntry dt,const char *name,const void **prop,unsigned *n) {
    static uint64_t range[2];(void)dt;assert(!strcmp(name,"b2l,wifi-firmware"));
    range[0]=(uintptr_t)firmware_fixture;range[1]=sizeof(firmware_fixture);
    if(firmware_fault==4)range[1]--;
    if(firmware_fault==5)range[0]++;
    if(firmware_fault==6)range[0]-=4096;
    if(firmware_fault==7)range[0]=UINT64_MAX&~4095ULL;
    if(firmware_fault==8)firmware_args.topOfKernelData--;
    *prop=range;*n=firmware_fault==3 ? 8:16;return firmware_fault==2 ? -1:0;
}
static uintptr_t ml_static_ptovirt(uint64_t base) {
    assert(base==(uintptr_t)firmware_fixture);return firmware_fault==9 ? 0:(uintptr_t)firmware_fixture;
}
void b2l_sha256(const void *p,size_t n,uint8_t digest[32]) {
    /* The real SHA implementation is independently exercised by cache tests.
     * Here control only authentication outcome, not hardware transactions. */
    static const uint8_t expected[32]={
        0x16,0x76,0xf4,0x6c,0xe5,0x6b,0x96,0xf5,0x8d,0xc7,0x0d,0xe0,0x8b,0xea,0xab,0x4a,
        0xb3,0x36,0x2e,0xe6,0xdd,0x75,0x14,0x65,0xa8,0xd6,0xa0,0x02,0x3c,0x3c,0x54,0xad};
    assert(p==firmware_fixture&&n==sizeof(firmware_fixture));memcpy(digest,expected,32);
    if(firmware_fault==10)digest[0]^=1;
}
