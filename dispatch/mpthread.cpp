#include<iostream>
#include<sstream>
#include<pthread.h>
#include<map>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<event.h>
#include<error.h>
#include<errno.h>
#include<event.h>
#include<fcntl.h>

#include "Const_hash.h"
#include "Node_s.h"
#include "cppjson.h"
#include "mpthread.h"

using namespace std;

//客户端发来包的回调函数
void cli_cb(int fd,short event,void* arg)
{
	Mpthread* mthis = (Mpthread*)arg;

	//收包
	char buf[128] = "";
	if( 0 >= recv(fd,buf,127,0) )
	{
		cout<<"client["<<fd<<"]close!"<<endl;
		close(fd);
	}
	
	//通过哈希获取服务器信息
	int n = rand();
	const char *ser_msg = ( mthis->get_server_msg(n,fd) ).c_str();
	
	int ser_fd = mthis->_ser_fd[ser_msg];
	send(ser_fd,buf,127,0);
}

//主线程发来套接字的回调函数
void sock_read_cb(int fd,short event,void* arg)
{
	Mpthread* mthis = (Mpthread*)arg;
	
	char cli_ip_fd[128] = {0};
	if( 0 > recv(fd,&cli_ip_fd,127,0) )
	{
		cerr<<"recv cli_fd fail;errno:"<<errno<<endl;
		return;
	}

    char *s = "";
    string ip(strtok(cli_ip_fd),"#");
    s = strtok(NULL,"#");
    int cli_fd = atoi(s);
    
    cli_ip.insert(map<int,sting>(cli_fd,ip));

	struct event* listen_event = event_new(mthis->_base,cli_fd,EV_READ|EV_PERSIST,cli_cb,mthis);
	
	event_add(listen_event,NULL);
}

void* thread_run(void* arg)
{
	Mpthread* mthis = (Mpthread*)arg;

    //初始化读取服务器数据
    json::Value val;
    int json_fd = open("./dispatch.json",O_RDONLY);
    if( -1 == json_fd )
    {
        cout<<"cout error"<<endl;
        return NULL;
    }

    //把每个服务器的信息保存
    string str;
    while(true)
    {   
        char buf[128] = ""; 
        if( !read(json_fd,buf,127) )
            break;
        str += buf;
    }   
    close(json_fd);
    std::istringstream ss(str);
    val.load_all(ss);
    vector<json::Value> sers = val.get("server").as_array();
    for(int i=0; i<sers.size(); ++i)
    {   
        map<string,string> m;
        m["ip"] = sers[i].as_object()["ip"].as_string();

        char buf[64] = ""; 
        sprintf(buf,"%d",sers[i].as_object()["port"].as_integer());
        m["port"] = buf;
        mthis->_servers.push_back(m);
    }

    //初始化哈希方法
    mthis->_method = val.get("balance_method").as_string();

    //create Node
    for(int i=0; i<_servers.size(); ++i)
    {
        string name = "server";
        char buf[10] = {0};
        sprintf(buf,"%d",i);
        name += buf;

        string ip_and_port = _servers[i]["ip"] + "#" +_servers[i]["port"];
        Node_s* node = new Node_s(name,50,ip_and_port);
        const_hash->addNode(node);
    }

	//与所有服务器建立连接
	for(int i=0; i< mthis->_servers.size(); ++i)
	{
		string ip = mthis->_servers[i]["ip"];
		string port_str = mthis->_servers[i]["port"];

        cout<<"ip"<<ip<<" port"<<port_str<<endl;

		int port = atoi(port_str.c_str());

		int fd = socket(AF_INET,SOCK_STREAM,0);
		if( -1 == fd )
		{
			cerr<<"fd create fail(connect ser);errno:"<<errno<<endl;
			return NULL;
		}

		struct sockaddr_in saddr;
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port);
		saddr.sin_addr.s_addr = inet_addr(ip.c_str());

		/*if( -1 == connect(fd,(struct sockaddr*)&saddr,sizeof(saddr)) );
		{
			cerr<<"connect fail(connect ser);errno:"<<errno<<endl;
			return NULL;
		}*/

        connect(fd,(struct sockaddr*)&saddr,sizeof(saddr));
        /*******************************************************/
        cout<<"connect ser success"<<endl;
        /*******************************************************/
        
		//将服务器信息和对应通信的fd保存，用来转发报文
		string aim_ser = ip + "#" + port_str;
		mthis->_ser_fd.insert(pair<string,int>(aim_ser,fd));
	}
	
	//监听主线程发来的套接字
	mthis->_base = event_base_new();

	struct event* listen_event = event_new(mthis->_base,mthis->_sock_read,EV_READ|EV_PERSIST,sock_read_cb,mthis);
	if( NULL == listen_event )
	{
		cerr<<"thread event new fail;errno:"<<errno<<endl;
		return NULL;
	}

	event_add(listen_event,NULL);

	event_base_dispatch(mthis->_base);
}

Mpthread::Mpthread(int sock_read)
{
	_sock_read = sock_read;

	pthread_t id;
	pthread_create(&id,NULL,thread_run,(void*)this);
}

string Mpthread::roundbin(int i)
{
    string res;
    int ser_num = _servers.size();
    res = _servers[i%ser_num]["ip"] + "#" + _servers[i%ser_num]["port"];
    return res;
}

string Mpthread::hash(int fd)
{
    string res;
    Node_s* node = const_hash->lookupNode_s(_cli_ip[fd]);
    return node->getData;
}

string Mpthread::get_server_msg(int i,int fd)
{
    if(_method == "poll")
    {
        return roundbin(i);
    }
    else if(_method = "hash")
    {
        return hash(fd);
    }
    else
    {
        cout<<"no hash"<<endl;
        return NULL;
    }
        
}
