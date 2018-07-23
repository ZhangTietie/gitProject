#include<iostream>
#include<errno.h>
#include<stdlib.h>
#include<string>
#include<string.h>
#include"dispatch.h"
using namespace std;

int main(int argc,char **argv)
{
	if(argc < 4)
	{
		cerr<<"dispatch's argv not enough"<<errno<<endl;
		return 0;
	}
	string ip = argv[1];
	unsigned short port = (unsigned short)atoi(argv[2]);
	int pth_num = atoi(argv[3]);

	Dispatch dispatch(ip.c_str(),port,pth_num);

	dispatch.run();
	return 0;
}
