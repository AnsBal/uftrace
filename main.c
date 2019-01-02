#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <iostream>
using namespace std;
void func(int a){
	int b = 2;	
	//printf("exit func\n");
}
int puts(const char*);
void foo(int a) {
	//int b =2;
	func(a);

	//printf("exit foo\n");
}

int main()
{
	int a = 2;
	while(1) {
		/*try
		  {
		    throw 20;
		  }
		  catch (int e)
		  {
		    cout << "An exception occurred. Exception Nr. " << e << '\n';
		  }*/
		//sleep(3);
		foo(1);
		//dlopen("/home/anas/Documents/Git/uftrace/libmcount/lib.so", RTLD_LAZY);
		//getenv("testname");
		//printf("testname:\n");		
	}
	return 0;
}



