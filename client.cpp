using namespace std;
#include <iostream>
#include <fstream>
#include <string> 
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(){
   int ret, fd;
   printf("Starting device client...\n");
   fd = open("/dev/ICMPDrop", O_RDWR);
   if (fd < 0){
      printf("Failed to open the device...");
      return -1;
   }

   fstream file;
   file.open("/root/ICMPMODULE/list.txt", ios::out | ios::in);
   string data;
   while(file >> data){
      cout << "write " << data << "to module" << endl;
      ret = write(fd, data.c_str(), data.size());
      if (ret < 0){
         printf("Failed to write the message to the device.");
         return -1;
      }
   }
   printf("End of the program\n");
   return 0;
}
