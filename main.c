#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
//#include <iostream>
//using namespace std;

void bar(int a){
}

void foo(int a) {
	bar(a);
}

int main()
{
	while(1) 
	{
//		try
//		{
//		   throw 20;
//		}
//		catch (int e)
//		{
//		  cout << "An exception occurred. Exception Nr. " << e << '\n';
//		}
		//sleep(1);
		foo(1);
		dlopen("/home/anas/Documents/Git/uftrace/libmcount/lib.so", RTLD_LAZY);	
	   	
		char command[50];
		strcpy( command, "wait" );
  		system(command);
	}
	return 0;
}



