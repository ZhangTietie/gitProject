#ifndef _VitualNode_s
#define _VitualNode_s
#include "Node_s.h"

class VirtualNode_s
{
public:
	VirtualNode_s();
	VirtualNode_s(Node_s *pNode);

	void setNode_s(Node_s *pNode);

	Node_s *getNode_s();

	void setHash(long pHash);

	long getHash();

private:
	long hash;	
	Node_s *node;
};
#endif
