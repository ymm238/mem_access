#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>

#define PAGE_SIZE       sysconf(_SC_PAGESIZE)
#define MAP_MASK        (PAGE_SIZE - 1)

// 参数结构体
struct mem_access_params {
    uintptr_t target_addr;
    char access_type;
    uint32_t write_value;
    bool write_mode;
};

// 内存映射上下文
struct mem_context {
    int fd;
    void *map_base;
    off_t page_base;
    off_t page_offset;
};

// 函数声明
void print_usage(const char *prog_name);
int parse_args(int argc, char **argv, struct mem_access_params *params);
int open_devmem(void);
void map_physical_memory(struct mem_context *ctx, uintptr_t target_addr);
void access_memory(struct mem_context *ctx, struct mem_access_params *params);
void cleanup(struct mem_context *ctx);

int main(int argc, char **argv) {
    struct mem_access_params params = {0};
    struct mem_context ctx = {0};
    
    // 解析命令行参数
    if (parse_args(argc, argv, &params) != 0) {
        return EXIT_FAILURE;
    }
    
    // 打开/dev/mem设备
    if ((ctx.fd = open_devmem()) < 0) {
        return EXIT_FAILURE;
    }
    
    // 映射物理内存
    map_physical_memory(&ctx, params.target_addr);
    
    // 执行内存访问操作
    access_memory(&ctx, &params);
    
    // 清理资源
    cleanup(&ctx);
    return EXIT_SUCCESS;
}

// 打印使用帮助
void print_usage(const char *prog_name) {
    fprintf(stderr, "Physical Memory Access Tool\n");
    fprintf(stderr, "Usage: %s -a <address> -t <type> [-v <value>]\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -a, --address    Physical address (hex)\n");
    fprintf(stderr, "  -t, --type       Access type: b(byte), h(halfword), w(word)\n");
    fprintf(stderr, "  -v, --value      Value to write (hex, omit for read)\n");
    fprintf(stderr, "  -h, --help       Show this help message\n\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  Read 32-bit from 0x1000: %s -a 0x1000 -t w\n", prog_name);
    fprintf(stderr, "  Write 16-bit 0xABCD to 0x2000: %s -a 0x2000 -t h -v 0xABCD\n", prog_name);
}

// 解析命令行参数
int parse_args(int argc, char **argv, struct mem_access_params *params) {
    int opt;
    struct option long_options[] = {
        {"address", required_argument, 0, 'a'},
        {"type", required_argument, 0, 't'},
        {"value", required_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "a:t:v:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                params->target_addr = strtoul(optarg, NULL, 0);
                break;
            case 't':
                params->access_type = tolower(optarg[0]);
                break;
            case 'v':
                params->write_value = strtoul(optarg, NULL, 0);
                params->write_mode = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    // 验证必须参数
    if (params->target_addr == 0 || 
        (params->access_type != 'b' && 
         params->access_type != 'h' && 
         params->access_type != 'w')) {
        fprintf(stderr, "Error: Missing or invalid required arguments\n");
        print_usage(argv[0]);
        return -1;
    }

    // 对齐检查
    if ((params->access_type == 'h' && (params->target_addr & 0x1)) ||
        (params->access_type == 'w' && (params->target_addr & 0x3))) {
        const char *type_str = (params->access_type == 'h') ? "16-bit" : "32-bit";
        fprintf(stderr, "Error: Address 0x%lX not aligned for %s access\n",
                (unsigned long)params->target_addr, type_str);
        return -1;
    }

    return 0;
}

// 打开/dev/mem设备
int open_devmem(void) {
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1) {
        fprintf(stderr, "Error opening /dev/mem: %s (Requires root privileges)\n", 
                strerror(errno));
        return -1;
    }
    return fd;
}

// 映射物理内存
void map_physical_memory(struct mem_context *ctx, uintptr_t target_addr) {
    // 计算页基地址和偏移量
    ctx->page_base = target_addr & ~MAP_MASK;
    ctx->page_offset = target_addr & MAP_MASK;

    // 映射内存页
    ctx->map_base = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, 
                        MAP_SHARED, ctx->fd, ctx->page_base);
    
    if (ctx->map_base == MAP_FAILED) {
        fprintf(stderr, "mmap error: %s\n", strerror(errno));
        close(ctx->fd);
        exit(EXIT_FAILURE);
    }
    
    printf("Mapped page (0x%lX) at virtual address: %p\n", 
           (unsigned long)ctx->page_base, ctx->map_base);
    printf("Target address 0x%lX -> Virtual address: %p\n", 
           target_addr, (void *)((uint8_t *)ctx->map_base + ctx->page_offset));
}

// 内存访问操作
void access_memory(struct mem_context *ctx, struct mem_access_params *params) {
    volatile void *virt_addr = (uint8_t *)ctx->map_base + ctx->page_offset;
    uint32_t read_result = 0;

    switch(params->access_type) {
        case 'b': 
            if (params->write_mode) {
                *(volatile uint8_t *)virt_addr = (uint8_t)params->write_value;
                printf("Wrote byte 0x%02X to address 0x%lX\n", 
                       (uint8_t)params->write_value, params->target_addr);
            }
            read_result = *(volatile uint8_t *)virt_addr;
            printf("Byte value at 0x%lX: 0x%02X\n", 
                   params->target_addr, read_result);
            break;
            
        case 'h':
            if (params->write_mode) {
                *(volatile uint16_t *)virt_addr = (uint16_t)params->write_value;
                printf("Wrote halfword 0x%04X to address 0x%lX\n", 
                       (uint16_t)params->write_value, params->target_addr);
            }
            read_result = *(volatile uint16_t *)virt_addr;
            printf("Halfword value at 0x%lX: 0x%04X\n", 
                   params->target_addr, read_result);
            break;
            
        case 'w':
            if (params->write_mode) {
                *(volatile uint32_t *)virt_addr = params->write_value;
                printf("Wrote word 0x%08X to address 0x%lX\n", 
                       params->write_value, params->target_addr);
            }
            read_result = *(volatile uint32_t *)virt_addr;
            printf("Word value at 0x%lX: 0x%08X\n", 
                   params->target_addr, read_result);
            break;
            
        default:
            fprintf(stderr, "Invalid access type '%c'. Use b, h, or w.\n", 
                    params->access_type);
            break;
    }
}

// 清理资源
void cleanup(struct mem_context *ctx) {
    if (ctx->map_base != MAP_FAILED) {
        if (munmap(ctx->map_base, PAGE_SIZE) == -1) {
            fprintf(stderr, "munmap error: %s\n", strerror(errno));
        }
    }
    
    if (ctx->fd >= 0) {
        close(ctx->fd);
    }
}
