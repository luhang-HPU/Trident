#include "memory_and_cpu.h"

int main(int argc, char **argv)
{
    MemOccupy mem_stat;
    CpuUsage cpu_usage;
    while (true)
    {
        auto cpu_use = cpu_usage.get_cpu_use();
        std::cout << "cpu:" << cpu_use * 100 << "%" << std::endl;  // 打印cpu的占用率

        // 获取内存
        get_mem_occupy((MemOccupy *)&mem_stat);
        cout << "mem_total: " << mem_stat.mem_total << "GB" << endl;
        cout << "mem_available: " << mem_stat.mem_available << "GB" << endl << endl;
        sleep(1);  // 延时1s；
    }
    return 0;
}

//  README
//  build: g++ -o memory_and_cpu memory_and_cpu.cpp
//  main is a demo
