#pragma once

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace std;

// 定义一个MemOccupy的结构体
struct MemOccupy
{
    char name1[20];
    double mem_total;  // 总内存
    char name2[20];
    double mem_free;
    char name3[20];
    double mem_available;  // 可用内存
    char name4[20];
    double buffers;
    char name5[20];
    double cached;
};

inline void get_mem_occupy(MemOccupy *mem)
{
    FILE *fd;
    char buff[512];
    MemOccupy *m;
    m = mem;
    fd = fopen("/proc/meminfo", "r");
    if (fd == NULL)
        return;

    fgets(buff, sizeof(buff), fd);
    if (strstr(buff, "MemTotal") != NULL)
        sscanf(buff, "%s %le ", m->name1, &m->mem_total);

    fgets(buff, sizeof(buff), fd);
    if (strstr(buff, "MemFree") != NULL)
        sscanf(buff, "%s %le ", m->name2, &m->mem_free);
    
    fgets(buff, sizeof(buff), fd);
    if (strstr(buff, "MemAvailable") != NULL)
        sscanf(buff, "%s %le", m->name3, &m->mem_available);
    
    fgets(buff, sizeof(buff), fd);
    if (strstr(buff, "Buffers") != NULL)
        sscanf(buff, "%s %le ", m->name4, &m->buffers);
    
    fgets(buff, sizeof(buff), fd);
    if (strstr(buff, "Cached") != NULL)
        sscanf(buff, "%s %le ", m->name5, &m->cached);

    mem->mem_total = mem->mem_total;
    mem->mem_free = mem->mem_free;
    mem->mem_available = mem->mem_available;
    mem->buffers = mem->buffers;
    mem->cached = mem->cached;
    fclose(fd);  // 关闭文件fd
}

struct CpuOccupy
{
    char name[20];        // 定义一个char类型的数组名name有20个元素
    unsigned int user;    // 定义一个无符号的int类型的user
    unsigned int nice;    // 定义一个无符号的int类型的nice
    unsigned int system;  // 定义一个无符号的int类型的system
    unsigned int idle;    // 定义一个无符号的int类型的idle
    unsigned int lowait;
    unsigned int irq;
    unsigned int softirq;
};

class CpuUsage
{
public:
    double get_cpu_use()
    {
        update_cpu_occupy();
        unsigned long od, nd;
        // 第一次(用户+优先级+系统+空闲)的时间再赋给od
        od = (unsigned long)(old_occupy.user + old_occupy.nice + old_occupy.system +
                             old_occupy.idle + old_occupy.lowait + old_occupy.irq +
                             old_occupy.softirq);
        // 第二次(用户+优先级+系统+空闲)的时间再赋给od
        nd = (unsigned long)(new_occupy.user + new_occupy.nice + new_occupy.system +
                             new_occupy.idle + new_occupy.lowait + new_occupy.irq +
                             new_occupy.softirq);
        double sum = nd - od;
        double idle = new_occupy.idle - old_occupy.idle;
        return (sum - idle) / sum;
    }

    void update_cpu_occupy()
    {
        old_occupy = new_occupy;

        FILE *fd;        // 定义打开文件的指针
        char buff[512];  // 定义个数组，用来存放从文件中读取CPU的信息
        CpuOccupy cpu_occupy;
        std::string cpu_use = "";
        fd = fopen("/proc/stat", "r");
        if (fd != NULL)
        {
            // 读取第一行的信息，cpu整体信息
            fgets(buff, sizeof(buff), fd);
            if (strstr(buff, "cpu") != NULL)  // 返回与"cpu"在buff中的地址，如果没有，返回空指针
            {
                // 从字符串格式化输出
                sscanf(buff, "%s %u %u %u %u %u %u %u", cpu_occupy.name, &cpu_occupy.user,
                       &cpu_occupy.nice, &cpu_occupy.system, &cpu_occupy.idle, &cpu_occupy.lowait,
                       &cpu_occupy.irq, &cpu_occupy.softirq);
                // cpu的占用率 = （当前时刻的任务占用cpu总时间-前一时刻的任务占用cpu总时间）/
                // （当前时刻 - 前一时刻的总时间）
                new_occupy = cpu_occupy;
            }
        }
        fclose(fd);
    }

    CpuOccupy old_occupy;
    CpuOccupy new_occupy;
};
