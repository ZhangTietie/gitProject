#include "Const_hash.h"
#include <assert.h>
#include "VirtualNode_s.h"
#include <string>
#include <cstring>
#include <cstdio>
#include <iostream>

char* itoa(int value, char* string, int radix)  
{  
    char tmp[33];  
    char* tp = tmp;  
    int i;  
    unsigned v;  
    int sign;  
    char* sp;  
  
    if (radix > 36 || radix <= 1)  
    {  
        //__set_errno(EDOM);  
        return 0;  
    }  
  
    sign = (radix == 10 && value < 0);  
  
    if (sign)  
        v = -value;  
    else  
        v = (unsigned)value;  
  
    while (v || tp == tmp)  
    {  
        i = v % radix;  
        v = v / radix;  
  
        if (i < 10)  
            *tp++ = i + '0';  
        else  
            *tp++ = i + 'a' - 10;  
    }  
  
    if (string == 0)  
        string = (char*)malloc((tp-tmp)+sign+1);  
    sp = string;  
  
    if (sign)  
        *sp++ = '-';  
  
    while (tp > tmp)  
        *sp++ = *--tp;  
    *sp = '\0';  
      
    return string;  
}   

Const_Hash::Const_Hash(Hash_Fun * pFunc)
{
	assert(pFunc!=NULL);
	this->HashFun = pFunc;
	this->vNodes = 0;
	
    vnode_tree = new util_rbtree_s();
	util_rbtree_init(vnode_tree);
}

void Const_Hash::setFunc(Hash_Fun * pFunc)
{
	this->HashFun = pFunc;
}

int Const_Hash::addNode_s(Node_s* pNode)
{
	if(pNode==NULL) return -1;
	int vCount = pNode->getVNodeCount();
	if(vCount<=0) return -1;
	VirtualNode_s * virtualNode ;
	util_rbtree_node_t * rbNode;
	char str [1000];
	char num[10];
	strcpy(str,pNode->getIpden());
	long hash = 0;
	
	for(int i=0;i<vCount;i++)
	{
		virtualNode = new VirtualNode_s(pNode);
		
		itoa(i,num,10);
		strcat(str,num);
		hash = HashFun->getHashVal(str);
		virtualNode->setHash(hash);
		if(!util_rbtree_search(vnode_tree,hash))
		{
			
			rbNode = vNode2RBNode(virtualNode); 
			if(rbNode!=NULL)
			{
				util_rbtree_insert(vnode_tree,rbNode);
				this->vNodes++;
			}
		}
	}
	return 0;
}

int Const_Hash::delNode_s(Node_s* pNode)
{
	if(pNode==NULL) return -1;
	util_rbtree_node_t * rbNode;
	char str [1000];
	char num [10];
	strcpy(str,pNode->getIpden()); 
	int vCount = pNode->getVNodeCount();
	long hash = 0;
	VirtualNode_s * node = NULL;
	
	for(int i=0;i<vCount;i++)
	{
		itoa(i,num,10);
		strcat(str,num);
		hash = HashFun->getHashVal(str);
		rbNode = util_rbtree_search(vnode_tree,hash);
		if(rbNode!=NULL)
		{
			node = (VirtualNode_s *) rbNode->data;
			if(node->getNode_s()==pNode && node->getHash()==hash)
			{
				this->vNodes--;
				
				util_rbtree_delete(vnode_tree,rbNode);
				delete rbNode;
				delete node;
			}
		}
	}
	return 0;
}


Node_s* Const_Hash::lookupNode_s(const char * object)
{
	if(object==NULL||this->vNodes==0) return NULL;
	util_rbtree_node_t * rbNode;
	int key = this->HashFun->getHashVal(object);
	
	rbNode = util_rbtree_lookup(vnode_tree,key);
	if(rbNode!=NULL)
	{
		return ((VirtualNode_s *)rbNode->data)->getNode_s();
	}
	return NULL;
}


int Const_Hash::getVNodes()
{
	return vNodes;
}






util_rbtree_node_t * vNode2RBNode(VirtualNode_s * vnode)
{
	if(vnode==NULL) return NULL;
	util_rbtree_node_t *rbNode = new util_rbtree_node_t(); 
	rbNode->key = vnode->getHash();
	rbNode->data = vnode;
	return rbNode;
}	
