# September 2024


## CVE-2024-38119
- Windows Network Address Translation (NAT) Remote Code Execution Vulnerability
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38119

```
CVSS: 7.5/6.5
CWE-416: Use After Free
Vulnerability Configuration Settings: NAT Configuration Required
Delivery Method: Repeated transmission of manipulated packets
```

The vulnerabilities CVE-2024-38119, CVE-2024-38045, and CVE-2024-21416 arise from the handling of arbitrary packets during the process of Windows performing Network Address Translation (NAT) functions. These vulnerabilities are triggered when Windows is configured to operate with NAT functionality through additional settings.

Network Address Translation (NAT) operates by forwarding packets between external and internal networks through two or more interfaces. Typically, NAT is used to enable machines within a private network to access the external internet via a physical Network Interface Card (NIC) or to forward connection requests from external sources to a specific port of a designated machine within the private network. However, NAT functionality can also be implemented on a single machine through the use of Hyper-V's Virtual Switch.

This functionality is handled by the tcpip.sys driver in Windows, and both this vulnerability and the two previously mentioned vulnerabilities were patched within tcpip.sys.


![1](https://github.com/user-attachments/assets/03cd138a-da64-460a-b642-c5964f520fa8)

This vulnerability occurs during the process of transmitting packets between external and internal networks in a NAT environment. Specifically, the issue arises during the handling of the IPv4 packet's option header in the source routing process for IPv4 packets. When mapped source IPs are either altered or unmapped during the packet forwarding process, it can lead to a Use After Free vulnerability by referencing freed memory.

Below is the path leading to the Ipv4ProcessOptionsPostForwarding function, which handles the processing of the IPv4 optional header during packet transmission in a NAT environment. Microsoft has applied the patch for this vulnerability to this function.


![2](https://github.com/user-attachments/assets/ae36293f-9cb2-4b99-8504-b40bbab36bd4)

To successfully exploit this vulnerability, the attacker must be able to transmit packets within the restricted NAT network zone.



## CVE-2024-38045
- Windows TCP/IP Remote Code Execution Vulnerability
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38045

```
CVSS: 8.1/7.1
CWE-122: Heap-based Buffer Overflow
Vulnerability Configuration Settings: NAT Configuration Required
Delivery Method: transmission of manipulated packets
```

As mentioned with the CVE-2024-38119 vulnerability, this vulnerability also occurs within NAT environments. It has likewise been patched in the tcpip.sys driver. In a NAT environment, when a manipulated packet is received, remote code execution may be possible.

This vulnerability arises during the process of handling packets received while performing NAT functions, leading to access of arbitrary heap memory. The vulnerability occurs in the function IppReceivePackets, where packets received are processed through the Forward Packet Chain List, which is responsible for handling packets that require bulk processing. This Chain List may point to a freed NET_BUFFER due to the manipulated packet. As a result, incorrect access to an MDL memory region may occur, allowing arbitrary code execution.

Below is the path leading to the specific code in the IppReceivePackets function that processes Forward Packets in a NAT environment.


![3](https://github.com/user-attachments/assets/eee09b6f-b2cf-4cb5-a9fb-40a4df5d7590)

To successfully exploit this vulnerability, the attacker must be able to transmit packets within the restricted NAT network zone.


## CVE-2024-21416
- Windows TCP/IP Remote Code Execution Vulnerability
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21416

```
CVSS: 8.1/7.1
CWE-122: Heap-based Buffer Overflow
Vulnerability Configuration Settings: NAT Configuration Required
Delivery Method: transmission of manipulated packets
```

This vulnerability also occurs during the process of handling the Chain List for packets that need to be processed simultaneously in a NAT environment.

The patch for this vulnerability has been applied to the IpIpsProviderForwardPackets and IppCompleteIpsReceiveContext functions. Notably, the IppCompleteIpsReceiveContext function is called during the process of handling the Forward Packet Chain List for L3 packets. An attacker, through manipulated packets, can cause both of these functions to reference an already freed NET_BUFFER_LIST, leading to the incorrect referencing of heap memory space.

Below is the path to reach the IppCompleteIpsReceiveContext function where the patch for this vulnerability has been applied.

![4](https://github.com/user-attachments/assets/11f2459b-93e6-44ed-ba2b-b6162b98b74e)

To successfully exploit this vulnerability, the attacker must be able to send packets within the restricted NAT network zone.


## CVE-2024-43454 / CVE-2024-38263/ CVE-2024-38260 / CVE-2024-43467
- Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43454 (CWE-23: Relative Path Traversal)
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38263 (CWE-591: Sensitive Data Storage in Improperly Locked Memory)
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38260 (CWE-908: Use of Uninitialized Resource)
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43467 (CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'))

```
CVSS: 8.1/7.1
Vulnerability Configuration Settings: Remote Desktop License Configuration Required
Delivery Method: Manipulated RPC Pakcets
```

![5](https://github.com/user-attachments/assets/819abbf1-6457-4e6f-81a2-14e8386ff405)


The four vulnerabilities mentioned above are successors to the multiple vulnerabilities patched in July for the Remote Desktop License Server (hereafter referred to as RDLicense). The RDLicense server performs the role of licensing and issuing certificates to multiple users/devices connecting to the Remote Desktop Session Host. Hosts performing the role of RD Session Host or Connection Broker communicate with the RDLicense Server over encrypted RPC via TLS to request license authentication and issuance. During this process, vulnerabilities can be triggered by sending arbitrarily manipulated RDLicense request packets through RPC.

Microsoft has applied patches for this vulnerability to lserver.dll (RD License Server) and mstlsapi.dll, the library responsible for TLS over RPC communication.

To successfully exploit this vulnerability, the attacker must have access to the RD License Server.

In relation to this vulnerability, last July, PatchPoint implemented PoC code for major RCE vulnerabilities. This is available to PatchPoint Subscription Plan subscribers. Additionally, a related video has been made public on the PatchPoint YouTube channel. Please refer to the link below.

- https://t.co/inicNHqOZE
- https://t.co/YVbgkHjL4W


## CVE-2024-38217
- Windows Mark of the Web Security Feature Bypass Vulnerability
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38217

```
CVSS: 5.4/5.0
CWE-693: Protection Mechanism Failure
Vulnerability Configuration Settings: None
Delivery Method: Manipulated LNK file
```

This vulnerability leverages a technique known as LNK Stomping, which involves manipulating LNK files to distribute them over the internet and execute arbitrary code. Specially crafted LNK files can bypass Windows' Mark of the Web (MotW) inspection, allowing the execution of arbitrary code without triggering security warnings like SmartScreen when the user clicks on the file.

For more information on this vulnerability, please refer to the URL below.
- https://www.elastic.co/security-labs/dismantling-smart-app-control

[Demo.mp4](https://github.com/user-attachments/assets/e60cccf8-8110-4ffa-b509-9e9ff0cb65a3)

Microsoft has applied patches for this vulnerability to windows.storage.dll and urlmon.dll.

![6](https://github.com/user-attachments/assets/54498b05-2c4d-414d-9b57-2bccfa5bc378)

This patch enforces the addition of a Mark of the Web (MotW) stamp when a manipulated LNK file is saved to the disk.

## CVE-2024-43461
- Windows MSHTML Platform Spoofing Vulnerability
- https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-43461

```
CVSS: 8.8/7.7
CWE-451: User Interface (UI) Misrepresentation of Critical Information
Vulnerability Configuration Settings: None
Delivery Method: .hta file
```

This vulnerability was discovered in the wild (ITW) in July 2024 and is able to bypass the patch for the CVE-2024-38112 vulnerability. The CVE-2024-38112 vulnerability exploits shortcut attack vectors, such as .url shortcuts, to execute URL paths like the one shown below, ultimately leading to the execution of script files such as .hta, prompting the user to run them.

```
https://domain.com/te/Books_A0UJKO.pdf%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80.hta
```

The CVE-2024-38112 vulnerability, as mentioned, allows attackers to insert the 0xA0 character into the URL path corresponding to an .hta file, thereby concealing the .hta file from the user and tricking them into opening it.

![7](https://github.com/user-attachments/assets/9a5dcdeb-3a2f-4de1-ab4e-6ec3039ef183)

Microsoft applied a patch for the CVE-2024-38112 vulnerability to the CDownloadUtilities::ShowOpenSaveTaskDialog function in ieframe.dll.

![8](https://github.com/user-attachments/assets/53b10f47-f110-453f-96d4-6ff4fa88e5ad)

The CVE-2024-43461 vulnerability still tricks users into opening .hta files by using the U+2060 (Word Joiner) in the URL path, similar to the previously mentioned vulnerability.

Microsoft applied a patch for this vulnerability to the CDownloadUtilities::ShowOpenSaveTaskDialog function in ieframe.dll. Additionally, to prevent the execution process from linking to .hta files, a patch was also applied to the CDownloadUtilities::OpenSafeOpenDialog function.


## CVE-2024-43495
- Windows libarchive Remote Code Execution Vulnerability
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43495

```
CVSS: 7.3/6.4
CWE-190: Integer Overflow or Wrapround
Vulnerability Configuration Settings: None
Delivery Method: manipulated RAR file
```

The recently disclosed vulnerability in Libarchive only affects Windows 11. It does not require any additional configuration and occurs in the default state of Windows 11. As a result, exploiting this vulnerability can allow arbitrary code execution for users running Windows 11.

Starting with the Windows 11 23H2 update, Microsoft introduced support for compressed files such as RAR, 7-zip, and tar.gz. It appears to be based on Libarchive from GitHub, which was appropriately modified for use.

This vulnerability occurs in archiveint.dll on Windows 11, marking the fourth vulnerability discovered in the Libarchive module this year. Most of the vulnerabilities have been related to the RAR-related code.

A notable point is that this vulnerability occurred in the execute_filter_rgb function, while a previous vulnerability occurred in the execute_filter_e8 function. Both are part of the filtering mechanism used in RAR's data compression technology (though the term "filter" is used differently in modern RAR compression technology). Consequently, to create a sample file to test this vulnerability, one would need to use older versions of RAR compression techniques and options.

![9](https://github.com/user-attachments/assets/d0297da4-6ef0-4517-ad18-5b307ec8b0c0)


## CVE-2024-43479
- Microsoft Power Automate Desktop Remote Code Execution Vulnerability
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43479

```
CVSS: 8.5/7.4
CWE-284: Improper Access Control
Vulnerability Configuration Settings: An Environment Using Power Platform and AD
Delivery Method: Logical
```

This vulnerability occurred in Power Automate and only affects machines joined to an Active Directory (AD) domain. It does not impact machines joined to Microsoft Entra ID.

![10](https://github.com/user-attachments/assets/e265fc1c-2511-4c04-b234-1ded1b2cec4f)

Power Automate is a service provided by Microsoft that helps users automate repetitive tasks and is part of the Microsoft Power Platform. It is a platform that allows users to create business solutions without any code. The patch in question affects the "Connect with sign-in" feature in Power Automate Desktop on devices joined to an Active Directory (AD) domain. It is noted that machines joined to Microsoft Entra ID are not affected. Microsoft Entra ID is the rebranded version of Azure Active Directory (Azure AD), a cloud-based identity and access management solution.

According to the Microsoft Advisory, the vulnerability occurs through the following process:
1. The attacker can register the target device with their own Entra Tenant if Power Automate is not already registered on the target device.
2. After registration, the attacker can extract the user's SID and use it to create an AD domain with the same SID.
3. The attacker then generates a valid Entra ID token using the AD domain with the same SID as the target device.
4. The issued token is considered trusted, allowing the attacker to execute arbitrary Desktop Flows scripts within the target device's session.

In conclusion, if the device is joined to an AD domain, is in an unlocked state, and the attacker successfully registers the device and triggers the vulnerability, they could remotely execute Desktop Flows scripts within Power Automate Desktop, potentially allowing arbitrary actions to be carried out or data to be stolen from the target device's session.



