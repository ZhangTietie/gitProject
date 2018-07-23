#include <iostream>
#include <sstream>
#include <unistd.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <error.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <map>
#include <pthread.h>
#include <event.h>
#include <fcntl.h>
#include <json/json.h>

#include "dispatch.h"
#include "mpthread.h"
using namespace std;

Dispatch::Dispatch(string ip,unsigned short port,int pth_num)
{
	int fd = socket(AF_INET,SOCK_STREAM,0);
	if( -1 == fd )
	{
		cerr<<"dispatch create socket fail;errno:"<<errno<<endl;
		return;
	}

	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = inet_addr(ip.c_str());

	if( -1 == bind(fd,(struct sockaddr*)&saddr,sizeof(saddr)) )
	{
		cerr<<"bind fail;errno:"<<errno<<endl;
		return;
	}
	
	if( -1 == listen(fd,20) )
	{
		cerr<<"listen fail;errno:"<<errno<<endl;
		return;
	}

	_listened_fd = fd;
	_pth_num = pth_num;

	_base = event_base_new();

	//随机数种子
	srand((unsigned)time(NULL));
}

//给主线程和支线程间创建管道
void Dispatch::create_pipe()
{
	for(int i=0; i<_pth_num; ++i)
	{
		int pipe_fd[2];
		if( -1 ==socketpair(AF_UNIX,SOCK_STREAM,0,pipe_fd) )
		{
			cout<<"pipe create error;errno:"<<errno<<endl;
		}
		sockPair sPair(pipe_fd[0],pipe_fd[1]);
        _pipe_base.push_back(sPair);
	}
}

void listen_cb(int fd,short event,void *arg);

void Dispatch::run()
{
    //create class Const_hash
    Hash_Fun * func = new CMD5HashFun();
    Const_Hash * const_hash = new Const_Hash(func);

	//创建线程的管道
	create_pipe();

	//创建线程
	//0端读，1端写，把0端给支线程
	for(int i=0; i<_pth_num; ++i)
	{
		int sock_read = _pipe_base[i][0];
		new Mpthread(sock_read);
	}
	
	//监听等待客户端connect
	struct event *listen_event = event_new(_base,_listened_fd,EV_READ|EV_PERSIST,listen_cb,(void*)this);
	if( NULL == listen_event )
	{
		cerr<<"listen_event create faile;errno:"<<errno<<endl;
		return;
	}

	//添加监听事件
	event_add(listen_event,NULL);

	//循环监听
	event_base_dispatch(_base);
}

void listen_cb(int fd,short event,void *arg)
{
	Dispatch *mthis = (Dispatch*)arg;

	struct sockaddr_in caddr;
	int len = sizeof(caddr);
	int cli_fd = accept(fd,(struct sockaddr*)&caddr,(socklen_t*)&len);

	if( -1 != cli_fd )
	{
		cout<<"client["<<cli_fd<<"],ip:"<<inet_ntoa(caddr.sin_addr)<<endl;
		int n = rand() % (mthis->_pth_num);
		int ser_fd = mthis->_pipe_base[n][1];

        char buf[128] = {0};
        sprintf(buf,"%d",cli_fd);
        string ip = inet_nota(caddr.sin_addr);
        ip = ip + "#" + buf
		send(ser_fd,&ip,ip.size(),0);
	}
}

