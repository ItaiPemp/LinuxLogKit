# LinuxLogKit

LinuxLogKit is a Linux kernel module that functions as a logger and rootkit. It provides capabilities for keylogging, network traffic logging, and concealing its presence within the system. Additionally, it offers system control features, such as hiding files, directories, processes, and kernel threads, as well as implementing a root backdoor for privileged access.
> :bulb: This project was created strictly for educational purposes, and learning about Linux kernel development.

## Features
### 1. Keylogging  
LinuxLogKit captures all keystrokes on the system and sends them to a remote server via UDP


![image](https://github.com/user-attachments/assets/1e37fdf4-a329-40c9-852e-940d8628add0)
### 2. Network Traffic Logging  
The module monitors outgoing HTTP and HTTPS network traffic and logs the data, sending it to a remote server. This feature provides insights into the system's outgoing communications. 


![image](https://github.com/user-attachments/assets/fdf2c703-83f0-4a98-b063-868af61e4f78)

### 3. Network Usage Hiding  
LinuxLogKit hides its network connections and activities, making them undetectable by tools like `netstat`, `tcpdump`, and `lsof`. This ensures its operations remain stealthy. 

![image](https://github.com/user-attachments/assets/6b6236cb-2609-4b98-92cf-c5462654b810)

### 4. File and Directory Hiding  
Specific files and directories associated with LinuxLogKit can be hidden, preventing detection or access by users and tools on the system.  


![image](https://github.com/user-attachments/assets/7f1774e9-c8be-4694-9e4b-ef9c2e79fb0f)

### 5. Process and Kernel Thread Hiding  
Processes and kernel threads created by LinuxLogKit are hidden from process-monitoring tools, such as `ps` and `top`, to maintain operational stealth. 

 ##### Before hiding:
![image](https://github.com/user-attachments/assets/bb1eda41-aeca-4232-85a8-a86599229f94)

##### After hiding:
![image](https://github.com/user-attachments/assets/8648fb48-8701-48ff-b0c0-4b0f295217ca)

### 6. Module Hiding from `lsmod`  
LinuxLogKit conceals itself from the kernel module list, making it invisible to `lsmod` and other tools that display loaded kernel modules.  

![image](https://github.com/user-attachments/assets/66038cbb-33ae-48c9-aea2-3204fde1aed8)


### 7. Root Backdoor via `sys_kill` Hijacking  
LinuxLogKit hijacks/hooks the `sys_kill` system call, enabling a backdoor that grants root privileges to authorized users for complete control of the system.  

![image](https://github.com/user-attachments/assets/c1b500ca-76b1-4cbc-9f8a-ab6acfa408d2)

## Compatibility and Testing  

LinuxLogKit was tested on **Linux kernel version 6.8** running on an **x64 architecture**. It is designed to work on previous kernel versions as well, though compatibility may vary depending on specific kernel configurations and distributions.  



## Disclaimer  

**This project was created strictly for educational purposes and to learn about Linux kernel development.**  









