#ifndef _MD5HashFun
#define _MD5HashFun

#include"Hash_fun.h"

class CMD5HashFun : public Hash_Fun
{
public:
	virtual long getHashVal (const char * );
};


#endif
