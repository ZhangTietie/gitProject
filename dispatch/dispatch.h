#include <iostream>
#include <map>
#include <vector>
#include <string>
using namespace std;

class sockPair
{
    public:
            sockPair(int first=0,int second=0)
                        :_first(first),_second(second){}
            ~sockPair(){}
            void operator=(sockPair &src)
                {   
                    _first = src._first;
                    _second = src._second;  
                }   
            int operator[](int index)
                {   
                    if(index == 0)
                        {   
                            return _first;
                        }   
                    else
                        return _second;
                }   
    private:
            int _first;//s[0] in the sockpair
            int _second;//s[1] int the sockpair
};


class Dispatch
{
	public:
		Dispatch(string ip,unsigned short port,int pth_num);
		void run();
		void create_pipe();
		void create_pth();

		friend void listen_cb(int fd,short event,void *arg);
	private:
		//监听客户端的连接
		struct event_base *_base;
		int _listened_fd;
		int _pth_num;
		//主线程和支线程传递套接字
		vector<sockPair> _pipe_base;
};
