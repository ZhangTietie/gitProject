dispatch:main.o json.o dispatch.o mpthread.o 
	g++ -o dispatch main.o json.o dispatch.o mpthread.o MD5.o Const_hash.o MD5HashFun.o Node_s.o RBTree.o VirtualNode_s.o -lpthread -levent -g

main.o:main.cpp
	g++ -c main.cpp -g

json.o:json.cc
	g++ -c json.cc -g

dispatch.o:dispatch.cpp
	g++ -c dispatch.cpp -g

mpthread.o:mpthread.cpp
	g++ -c mpthread.cpp -g

MD5.o:MD5.cpp
	g++ -c MD5.cpp -g

Const_hash.o:Const_hash.cpp
	g++ -c Const_hash.cpp -g

MD5HashFun.o:MD5HashFun.cpp
	g++ -c MD5HashFun.cpp -g

Node_s.o:Node_s.cpp
	g++ -c Node_s.cpp -g

RBTree.o:RBTree.cpp
	g++ -c RBTree.cpp -g

VirtualNode_s.o:VirtualNode_s.cpp
	g++ -c VirtualNode_s.cpp -g

clean:
	rm -fd *.o dispatch
