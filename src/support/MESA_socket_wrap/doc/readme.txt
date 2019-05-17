MESA_socket_wrap 说明:

主要功能:
1)解决select(2)对最大fd限制, 在dpdk平台下无法使用;
2)对常用的系统标准socket接口，增加带超时的非阻塞操作.
3)ssize_t read(int fd, void *buf, size_t count); 
  ssize_t write(int fd, const void *buf, size_t count); 
 以上是read和write的标准接口，
 在基于TCP SOCKET通信时，即使网络不出现错误，上述两个函数的返回值，也非常有可能不等于参数'count'，
 在实际使用时，这个特性让应用程序处理起来很麻烦，
 MESA_socket_wrap 库提供两个新接口：
 MESA_sock_greedy_read 和 MESA_sock_force_write，使调用者实际接收或发送的值一定等于'count'.
4)MESA_sock_xxx系列函数只是对标准SOCKET库的再封装，
  在一个程序内，根据需求的不同，可以和标准SOCKET库混合使用.
  如：
	......;

	int fd = socket(xxx);
	ret = read(fd, xxx);
	ret = MESA_sock_force_write(fd, xxx);

	......;

和MESA_tcp库的区别:
  MESA_tcp库使调用者无需考虑connect、bind、listen、accept等操作，使复杂的TCP通信类似UDP一样简单易用。
  但MESA_tcp隐藏了socket一些通信细节，句柄对上层应用不透明。
  根据实际需求选择具体使用哪类库.  


Update History:
-----------------------------------------------------------------------------
2014-07-15 LiJia
1)修改epoll_wait()被其他fd唤醒但不是interest-fd的BUG，此时应重试.
