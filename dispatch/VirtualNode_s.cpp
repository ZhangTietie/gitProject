#include "VirtualNode_s.h"
#include <assert.h>
#include <iostream>

VirtualNode_s::VirtualNode_s()
{
	hash = -1;
	node = NULL;
}
VirtualNode_s::VirtualNode_s(Node_s *pNode)
{
	setNode_s(pNode);
}

void VirtualNode_s::setNode_s(Node_s *pNode)
{
	assert(pNode != NULL);
	node = pNode;
}

Node_s * VirtualNode_s::getNode_s()
{
	return node;
}

void VirtualNode_s::setHash(long pHash)
{
	hash = pHash;
}

long VirtualNode_s::getHash()
{
	return hash;
}
