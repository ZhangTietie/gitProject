#ifndef _Const_Hash_
#define	_Const_Hash_
#include <map>
#include "Node_s.h"
#include "Hash_fun.h"
#include "RBTree.h"
#include "VirtualNode_s.h"

class Const_Hash
{
public:
	Const_Hash(Hash_Fun * pFunc);

	void setFunc(Hash_Fun * pFunc);

	int addNode_s(Node_s* pNode);

	int delNode_s(Node_s* pNode);

	Node_s* lookupNode_s(const char * objec);

	int getVNodes();

private:
	Hash_Fun *HashFun;

	int vNodes;

	util_rbtree_t * vnode_tree;
}; 
util_rbtree_node_t * vNode2RBNode(VirtualNode_s * vnode);
#endif
