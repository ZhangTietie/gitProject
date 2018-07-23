#ifndef _MPTHREAD_H_
#define _MPTHREAD_H_
#include <map>
#include <string>
#include <vector>
#include <event.h>
using namespace std;

class Mpthread
{
	public:
		Mpthread(int sock_read);
        string hash(int fd);
        string roundbin(int i);
		string get_server_msg(int i);
		string get_dispatch_method();
		string roundbind(int i);
	
    private:
		//接收主线程发来fd的管道文件描述符
		int _sock_read;
		//监听客户端发数据
		struct event_base* _base;
		//线程与所有服务器建立连接
		map<string,int> _ser_fd;

        //client's map<fd,ip>
        map<int,string>_cli_ip;

        //服务器信息
        vector< map<string,string> >_servers;
        string _method;

        friend void cli_cb(int fd,short event,void *arg);
        friend void sock_read_cb(int fd,short event,void *arg);
        friend void* thread_run(void *arg);
};
#endif
