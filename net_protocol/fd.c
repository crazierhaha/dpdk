#include "fd.h"

// 自定义 fd 相关参数
#define FILE_DESC_TABLE_SIZE 256

// 标准输入、标准输出、标准错误 相同的 fd  默认不分配
static unsigned char g_fd_table[FILE_DESC_TABLE_SIZE] = { 1, 1, 1 };

int get_fd(void) {
	for (int i = 0; i < FILE_DESC_TABLE_SIZE; i++) {
		if (!g_fd_table[i]) {
			g_fd_table[i] = 1;
			return i;
		}
	}

	return -1;
}

void reset_fd(int fd) {
	g_fd_table[fd] = 0;
}

