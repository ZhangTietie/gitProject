#include "Node_s.h"
#include <string.h>
#include <assert.h>

Node_s::Node_s():vNodeCount(0),data(NULL)
{
}

Node_s::Node_s(char *pIden ,int pVNodeCount ,void *pData)
{
	setNode(pIden ,pVNodeCount ,pData);
}

void Node_s::setNode(char *pIden ,int pVNodeConut ,void *pData)
{
	assert(pIden != NULL && pVNodeConut>0);
	strcpy(iden,pIden);
	vNodeCount = pVNodeConut;
	data = pData;
}

void Node_s::setData(void *pData)
{
	data = pData;
}

const char* Node_s::getIpden()
{
	return iden;
}

int Node_s::getVNodeCount()
{
	return vNodeCount;
}

void * Node_s::getData()
{
	return data;
}
