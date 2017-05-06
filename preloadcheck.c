#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"

int main(int argc, char *argv[]) {
 void *libc = dlopen(LIBC, RTLD_LAZY); // Open up libc directly
 char *syscalls[] = {"open", "readdir", "fopen", "accept", "access", "unlink"};
 int i;
 void *(*libc_func)();
 void *(*next_func)();

 for (i = 0; i < 6; ++i) {
  printf("[+] Checking %s syscall.\n", syscalls[i]);
  libc_func = dlsym(libc, syscalls[i]);
  next_func = dlsym(RTLD_NEXT, syscalls[i]);
  if (libc_func != next_func) {
   printf("[!] Preload hooks dectected!\n");
   printf("Libc address: %p\n", libc_func);
   printf("Next address: %p\n", next_func);
  }
 }

 return 0;
}
