#!/usr/bin/env python3
"""Exercise the real EFI BOOT reader with bounded synthetic block devices."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
source = (repo / 'uefi/XnuLoader/BootPayload.c').read_text()
source = '\n'.join(s for s in source.splitlines() if not s.startswith('#include'))
pre = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include "BootMetadata.h"
#define STATIC static
#define CONST const
#define VOID void
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef size_t UINTN;
typedef int EFI_STATUS;
typedef void *EFI_HANDLE;
typedef unsigned EFI_DEVICE_PATH_PROTOCOL;
#define B2L_BOOT_SEED_SIZE 256u
#define MAX_UINT32 UINT32_MAX
#define MAX_UINT64 UINT64_MAX
#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER 1
#define EFI_NOT_FOUND 2
#define EFI_COMPROMISED_DATA 3
#define EFI_OUT_OF_RESOURCES 4
#define EFI_DEVICE_ERROR 5
#define EFI_ERROR(x) ((x)!=0)
#define PARTITION_TYPE_GPT 1
#define ByProtocol 0
static int gEfiBlockIoProtocolGuid, gEfiDiskIoProtocolGuid;
static int gEfiPartitionInfoProtocolGuid, gEfiDevicePathProtocolGuid;
static unsigned allocations, fail_allocate, fail_read;
static void *AllocatePool(size_t n) {
    if(n==fail_allocate)return NULL;
    void *p=malloc(n);assert(p);allocations++;return p;
}
static void FreePool(void *p){assert(p&&allocations);allocations--;free(p);}
#define ZeroMem(p,n) memset(p,0,n)
#define CopyMem(p,q,n) memcpy(p,q,n)
#define CompareMem(p,q,n) memcmp(p,q,n)
#define Print(...) ((void)0)
static UINTN GetDevicePathSize(EFI_DEVICE_PATH_PROTOCOL *p){(void)p;return 0;}
static int b2l_boot_ufs_lun(const void*p,size_t n,UINT32*lun){(void)p;(void)n;(void)lun;return -1;}
typedef struct { unsigned MediaPresent,LogicalPartition,BlockSize;UINT64 LastBlock;UINT32 MediaId; } MEDIA;
typedef struct { MEDIA *Media; } EFI_BLOCK_IO_PROTOCOL;
typedef struct DISK EFI_DISK_IO_PROTOCOL;
struct DISK { EFI_STATUS (*ReadDisk)(EFI_DISK_IO_PROTOCOL *,UINT32,UINT64,UINTN,VOID *); };
typedef struct {unsigned Type;struct {struct {wchar_t PartitionName[36];} Gpt;} Info;} EFI_PARTITION_INFO_PROTOCOL;
static uint8_t image[2*1024*1024];
static unsigned reads;
static EFI_STATUS read_disk(EFI_DISK_IO_PROTOCOL *d,UINT32 id,UINT64 at,UINTN n,VOID*out) {
    (void)d;assert(id==9);reads++;
    assert(at<=sizeof(image)&&n<=sizeof(image)-at);
    if(reads==fail_read)return EFI_DEVICE_ERROR;
    memcpy(out,image+at,n);return 0;
}
static MEDIA media;
static EFI_BLOCK_IO_PROTOCOL block={&media};
static EFI_DISK_IO_PROTOCOL disk={read_disk};
static EFI_PARTITION_INFO_PROTOCOL partition;
static EFI_STATUS locate(unsigned by,const void *guid,void *key,UINTN *n,EFI_HANDLE **handles) {
    assert(!by&&guid==&gEfiBlockIoProtocolGuid&&!key);*n=1;
    *handles=AllocatePool(sizeof(**handles));(*handles)[0]=(void*)1;return 0;
}
static EFI_STATUS protocol(EFI_HANDLE h,const void *guid,void **out) {
    assert(h==(void*)1);
    if(guid==&gEfiBlockIoProtocolGuid)*out=&block;
    else if(guid==&gEfiDiskIoProtocolGuid)*out=&disk;
    else if(guid==&gEfiPartitionInfoProtocolGuid)*out=&partition;
    else return EFI_NOT_FOUND;
    return 0;
}
typedef struct {EFI_STATUS(*LocateHandleBuffer)(unsigned,const void*,void*,UINTN*,EFI_HANDLE**);
 EFI_STATUS(*HandleProtocol)(EFI_HANDLE,const void*,void**);} SERVICES;
static SERVICES services={locate,protocol};
static SERVICES *gBS=&services;
'''
post = r'''
static void le32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void le64(uint8_t*p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static void reset(int fw) {
    assert(!allocations);memset(image,0,sizeof(image));reads=fail_allocate=fail_read=0;
    media=(MEDIA){1,1,512,sizeof(image)/512-1,9};
    partition.Type=PARTITION_TYPE_GPT;
    static const wchar_t boot[]=L"BOOT";memcpy(partition.Info.Gpt.PartitionName,boot,sizeof(boot));
    memcpy(image,"ANDROID!",8);le32(image+8,4096);le32(image+36,2048);le32(image+40,1);
    uint8_t *p=image+6144;memcpy(p,"B2LXNU02",8);le32(p+8,2);le32(p+12,320);le64(p+16,4096);le64(p+24,320);
    for(unsigned i=0;i<256;i++)p[32+i]=(uint8_t)i;
    le32(p+320,0xfeedfacf);le32(p+324,0x0100000c);
    if(fw){memcpy(p+288,"B2LWIFI1",8);p[296]=2;p[301]=1;
      memcpy(p+302,"B2LFW001",8);le32(p+310,B2L_WIFI_FIRMWARE_BYTES);
      memset(p+320+4096,0x5a,B2L_WIFI_FIRMWARE_BYTES);}
}
static EFI_STATUS run(unsigned expect_firmware) {
    void *k=(void*)1,*f=(void*)1;size_t n=123,fn=123;uint8_t seed[256],mac[6];
    EFI_STATUS s=B2lLoadBootPayload(&k,&n,seed,mac,&f,&fn);
    if(s){assert(!k&&!f&&!n&&!fn);}
    else {assert(n==4096&&!memcmp(k,image+6144+320,n));
      for(unsigned i=0;i<256;i++)assert(seed[i]==(uint8_t)i);
      if(expect_firmware){assert(fn==B2L_WIFI_FIRMWARE_BYTES&&f&&mac[0]==2&&mac[5]==1);
        for(size_t i=0;i<fn;i++)assert(((uint8_t*)f)[i]==0x5a);
        FreePool(f);}
      else assert(!f&&!fn);
      FreePool(k);}
    assert(!allocations);return s;
}
int main(void) {
    reset(0);assert(run(0)==0&&reads==3);
    reset(1);assert(run(1)==0&&reads==4);
    reset(0);memset(image+6144+320+4096,0x5a,B2L_WIFI_FIRMWARE_BYTES);
    assert(run(0)==0&&reads==3); /* Stale tail is not an opt-in. */
    for(unsigned i=14;i<32;i++){reset(1);image[6144+288+i]^=1;assert(run(0)==EFI_COMPROMISED_DATA);}
    reset(1);media.LastBlock=(6144+320+4096+B2L_WIFI_FIRMWARE_BYTES)/512-1;
    assert(run(0)==EFI_COMPROMISED_DATA&&reads==2);
    reset(1);fail_allocate=B2L_WIFI_FIRMWARE_BYTES;assert(run(0)==EFI_OUT_OF_RESOURCES);
    reset(1);fail_read=4;assert(run(0)==EFI_DEVICE_ERROR);
    reset(1);le32(image+6144+320,0);assert(run(0)==EFI_COMPROMISED_DATA);
    reset(1);le64(image+6144+16,UINT64_MAX);assert(run(0)==EFI_COMPROMISED_DATA);
    reset(1);le64(image+6144+24,UINT64_MAX);assert(run(0)==EFI_COMPROMISED_DATA);
    reset(0);memcpy(image+6144,"B2LXNU01",8);assert(run(0)==EFI_COMPROMISED_DATA);
    reset(1);media.LastBlock=UINT64_MAX;assert(run(0)==EFI_NOT_FOUND&&!reads);
    puts("EFI BOOT reader: explicit firmware opt-in, partition bounds, failed reads/allocations and complete cleanup passed");
}
'''
with tempfile.TemporaryDirectory(prefix='b2l-efi-boot-') as temp:
    path = Path(temp) / 'test.c'
    binary = Path(temp) / 'test'
    path.write_text(pre + source + post)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-I', str(repo / 'uefi/XnuLoader'),
        str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
