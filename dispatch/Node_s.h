#ifndef	_Node_s 
#define _Node_s

class Node_s
{
public:
	Node_s();
	Node_s(char *pIden ,int pVNodeCount ,void *pData);

	const char *getIpden();

	int getVNodeCount();

	void setData(void *pData);

	void *getData();


private:
	void setNode(char *Ipden ,int pVNodeCount,void *pData);
	char iden[30];
	int vNodeCount;
	void *data;/*serverIP*/
};
#endif
