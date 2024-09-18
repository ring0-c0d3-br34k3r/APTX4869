# APTX4869: The Never Ending Driver

## The Never Ending Driver
**"APTX4869"** is a x64 Ring 0 rootkit designed to achieve extreme persistence and stealth in system environments. It leverages deep kernel manipulation techniques to hide its presence, making it virtually impossible to detect or unload without a full system reboot. This rootkit modifies critical kernel structures and employs anti-detection mechanisms, ensuring that even sophisticated monitoring tools struggle to identify its presence.

### Advanced Stealth and Persistence
The **APTX4869** rootkit uses several advanced methods to remain hidden and active within the system, including:

- **Unlinking from `PsLoadedModuleList`**: The rootkit removes itself from the Windows `PsLoadedModuleList`, making it invisible to most kernel-level tools that list loaded drivers. This technique effectively hides the driver from standard enumeration methods used by security products.
  
- **Hidden Object Directory**: The rootkit creates and relocates itself into a hidden object directory (`\\KernelObjects\\HidRkDriver`). This directory is not typically visible or accessible through conventional user-mode or kernel-mode tools, adding another layer of stealth.

- **Anti-Unload Mechanisms**: Any attempt to unload the driver can result in a system crash (BSOD), providing strong resistance against removal. It alters kernel structures, making driver unloading extremely difficult without full system reboot.

- **System Reboot Required**: Complete removal of the rootkit is only achievable through a system reboot, as it hooks deeply into critical kernel functions to ensure persistence during operation.

### Key Features

- **Driver Unlinking from Kernel Lists**: Unlinks from the `PsLoadedModuleList` to hide its presence in kernel-mode listings.
  
- **Hidden Directory Creation**: Creates a hidden directory within `\\KernelObjects`, where the rootkit resides, making it harder to locate.
  
- **Preventing Driver Unloading**: Tampering with the rootkit leads to system instability and crashes (BSOD), ensuring its persistence in the system.

- **Reboot-Resistant**: The rootkit remains active and invisible until a complete system reboot is performed. 

- *More advanced techniques to be integrated soon.*


## **Log File Support (Issue: Debug Printing)**
- One of the challenges encountered during development was reliable debug printing in the kernel. Debug print outputs (`DbgPrint`) sometimes fail or don't display correctly in certain environments. To solve this, the rootkit implements a log file system that captures key events and errors during operation.

- **Persistent Log File**: Events are logged to a file on the disk, which serves as a reliable way to debug and monitor the driver’s activities.
  
- **Issue with Debug Printing**: In kernel debugging, there are known limitations with `DbgPrint` and its output visibility, especially when dealing with kernel-mode drivers. In response, a logging mechanism was developed that writes logs directly to a file, bypassing the inconsistent debug print behavior.


### Final Point
APTX4869 is designed for highly advanced persistence and stealth in Windows environments. Once loaded, it can be removed only through reboot, making it a formidable rootkit for long-term control over compromised systems. This driver is continually evolving, with more stealth and persistence features being developed for future releases.
