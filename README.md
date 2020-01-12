# Network_loadable_kernel_module
TCP/UDP packet drop kernel module

## Overview
The main tool used in this project is Netfilter Hooks which is a framework for packet mangling, outside the normal Berkeley socket interface. First, each protocol defines "hooks" which are well-defined points in a packet's traversal of that protocol stack. At each of these points, the protocol will call the netfilter framework with the packet and the hook number.
There are 5 different kinds of netfilter hooks:

**1.NF_IP_PER_ROUTING**: *This hook called when a packet arrives into the machine.*

**2.NF_IP_LOCAL_IN**: *This hook is called when a packet is destined to the machine itself.*

**3.NF_IP_FORWARD**: *This hook is called when a packet is destined to another interface.*

**4.NF_IP_POST_ROUTING**: *Called when a packet is on its way back to the wire and outside the machine.*

**5.NF_IP_LOCAL_OUT**: *When a packet is created locally, and is destined out, this hook is called.*


## Goal
The goal is to write a simple kernel module which each time a packet arrives, it investigates it to find out the source port and according to a provided black or white list(determined by a chosen policy), it decides whether to drop the packet or not.

## Code Summery
The raw project (before compilation) consists of 3 files:

**1.** `client.cpp` which at the beginning determines the policy( using a black list or a white list) and then fills the aforementioned list and provides it to the driver.

2.`ICMPDrop.c` which registers the device by getting a major number for the driver from the operating system.Each time a packet arrives,it uses the Netfilter tool briefly described above and decide wheter to accept the packet or not( according to chosen policy). In each case, it prints the result in kernel logs using `printk`. Finally when being unloaded from the kernel it unregisters the device.

3.`Makefile` For compiling this loadable kernel module we use something called Makefile, which is a file that contains instructions and settings that will be later read and executed by the `make` command in the `bash`

## Requirements
Install required packages for module compilation using:

 ```
 sudo apt-get install build-essential linux-headers-$(uname -r)
  ```

## Steps To Run 
  * ### 0-Cloning
      + First of all clone the project : 

 ```
 git clone https://github.com/bahar99/Network_loadable_kernel_module
  ```

* ### 1-Getting Our Code Ready : 
    + Compiling the client code using `g++ client.cpp`
    + Compiling the ICMPDrop.c and creating the objects using `make`
    

* ### 2-Loading the module : 

 ```
 sudo insmod ICMPDrop.ko
  ```
  
 * ### 3-Running the client code : 
     + You can provide your chosen black/white list to the driver by running the client code.
 

 * ### 4-More commands:
      + You can clean up the module any time using `make clean`
      + Unloading the driver is possible using:
  ```
 sudo rmmod ICMPDrop
  ```
## Sources
* Dr.Zali LKM code in lms
* Codes and Videos Provided in OSLAB telegram channel
* [Medium](https://medium.com/@GoldenOak/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e)
* [Danisfermi firewall github example](https://github.com/danisfermi/firewall-kernel-module)
* [DerekMolloy](http://derekmolloy.ie/writing-a-linux-kernel-module-part-1-introduction/)
* [introduction to major and minor number](https://www.oreilly.com/library/view/linux-device-drivers/0596000081/ch03s02.html)
* [Geeksforgeeks hello world kernel module](https://www.geeksforgeeks.org/linux-kernel-module-programming-hello-world-program/)
## Support
Reach out to me at boroomand.bahar@yahoo.co.uk
