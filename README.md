# TheNidavellirProject-Free  

### Overview  
The Nidavellir Project is a robust and free tool designed to fix numerous bugs and vulnerabilities in **Call of Duty: Black Ops 3**, particularly focusing on multiplayer and lobby systems. It addresses critical issues like invalid packet handling, buffer overflows, and crash exploits to enhance gameplay stability and security.

### Features  
- Fixes improper message handling in lobby communication.  
- Mitigates vulnerabilities like buffer overflows and invalid memory accesses.  
- Prevents crashes caused by malformed or malicious packets.  
- Implements security checks to detect and stop exploit attempts.  
- Free and open-source for the community.

---

### Patches  

#### **Crash and Popup Prevention for Malformed Packets in `dwInstantDispatchMessage offset(0x143A600)`**  

**Problem**:  
The crash occurs when malformed or empty messages are sent via the `dwInstantDispatchMessage` function, which processes messages in multiplayer sessions. These messages can lead to crashes if they are empty, contain invalid data, or are sent in a way that bypasses size validation. .

**Solution**:  
The patch prevents this issue by adding additional checks to the message processing flow:

- **Empty Message Handling**: The patch ensures that messages which are empty or contain only whitespace are ignored, preventing processing of invalid data.
  
- **Invalid Message Size Handling**: Messages that don't match the expected size or have an invalid read count are discarded. This prevents potential buffer overflows and memory corruption.

- **Message Type Validation**: The patch checks for specific message types and sizes, ensuring only valid messages are processed. Suspicious message types or incorrect sizes are ignored:

  - **Type `102`**: This is identified as a crash message type. If a message of this type is received with size 102, the patch prevents it from being processed to avoid crashing the game.
  
  - **Type `2`**: This type corresponds to a popup message, which is blocked to prevent disruptive popups during gameplay.

  - **Type `e`**: This type corresponds to remote command buffer (Cbuf) messages, which can be exploited remotely. The patch ensures that these messages are ignored to prevent potential misuse.

- **Overflow Protection**: Additional checks are added to prevent buffer overflow scenarios when handling message data. If an overflow is detected, the message is discarded to prevent a crash.

---

#### **Preventing Invalid or Malicious Connectionless Packets in `CLDispatchConnectionlessPacket offset(0x134CD50)`**

**Problem**:  
Connectionless packets, such as voice type or other non-standard packets, can be exploited to send malicious data that can potentially disrupt the game. The issue occurs when invalid or unauthorized packets are processed by the `CLDispatchConnectionlessPacket` function. This can lead to unwanted behaviors, including crashes or unauthorized actions.

**Solution**:  
The patch adds the following safeguards to handle connectionless packets:

- **Voice Type Packet Handling**: The patch ensures that only valid voice packets are processed by the `CLHandleVoiceTypePacket` function. Any invalid packets are ignored, preventing potential abuse of voice packets.

- **Command Argument Validation**: The patch validates the arguments in connectionless commands. It ensures that only legitimate command arguments are allowed. If invalid or malformed arguments are detected, the packet is ignored, and an underflow prevention mechanism is triggered.

- **Legitimate Packet Check**: The patch verifies the legitimacy of the packet type by checking if the first argument matches a predefined list of known valid packet types. If an invalid packet is detected, it is discarded, and the source IP address is logged for security purposes.

- **Security Logging**: Invalid packets from untrusted sources are logged with their originating IP address, which helps monitor suspicious activity and prevent exploit attempts.

---

#### **Preventing Invalid or Malicious Server Command Packets in `SVClientCommandPacket offset(0x2253E00)`**

**Problem**:  
Similar to connectionless packets, server-side command packets can also be exploited by attackers to disrupt the server or execute remote actions. These server command packets can carry invalid data or commands that bypass normal validation, allowing malicious packets to affect the server. The issue arises when such packets are processed by the `SVClientCommandPacket` function.

**Solution**:  
This patch applies similar checks to those used in connectionless packet handling, but specifically targets server-side commands:

- **Command Validation**: The patch ensures that only valid server command packets are processed. If the command packet is invalid or contains unauthorized data, it is discarded.

- **Message Type Check**: The patch checks the packet type and ensures that it matches expected valid types. Invalid packets are ignored to prevent potential exploitation.

- **IP Address Logging**: Malicious or invalid packets from unauthorized sources are logged with their originating IP address, helping detect and prevent server-side exploit attempts.

- **Overflow Protection**: The patch also includes overflow protection to handle potentially oversized or malformed server command packets. If any overflows are detected, the packet is discarded to prevent crashes or unintended behavior.

---

#### **Material Management Fixes**

**Problem**:  
Malformed material or model strings in the game can lead to issues such as invalid replacements or rendering errors. Improper paths, invalid sequences, and incorrect model names can cause crashes or unwanted behaviors when processing material and model-related data. This can also affect the game's user interface and overall stability, especially when dealing with dynamic asset loading and replacement operations.

**Solution**:  
This patch improves the material management system by adding robust validation and handling for material and model strings. It introduces additional checks to prevent crashes and rendering issues caused by invalid or malformed data:

- **Pattern Type Detection**:  
  The patch introduces a system to detect various pattern types within material and model strings. The patterns are identified based on specific byte sequences, and each pattern is categorized into one of the following types:
  
  - **InvalidMaterial**: Identifies strings that match invalid material patterns and replaces them with a predefined invalid material string.
  - **InvalidModel**: Identifies strings that match invalid model patterns and replaces them with a predefined invalid model string.
  - **InvalidSequence**: Identifies invalid sequences of characters in model strings and replaces them to prevent issues with loading or rendering.
  - **InvalidLocalization**: Identifies invalid localization patterns (e.g., misformatted localization strings) and replaces them with predefined invalid localization strings.
  - **Valid**: Strings that pass the validation are considered valid and remain unchanged.

- **Model String Replacement**:  
  The `UI_DoModelStringReplacement offset(0x1F334C0)` function handles the replacement of invalid material or model strings with appropriate fallback strings. It checks for invalid patterns in the input string and applies the corresponding replacement based on the detected pattern type. If the string is valid, it remains unchanged. The patch ensures that invalid strings do not propagate through the system, avoiding rendering issues or crashes.

- **Path Pattern Validation**:  
  The patch also validates the paths used in material or model references. It checks the length of node names and ensures that there are no excessive dot sequences (e.g., `..`) or invalid node name lengths. Paths that fail these checks are considered invalid and are not processed, preventing errors during model or material loading.

- **Overflow Protection**:  
  Additional checks are added to prevent buffer overflows when handling strings. The patch ensures that strings are safely copied into destination buffers, and if the size exceeds the allocated buffer, the copy operation is truncated. This helps prevent crashes due to invalid memory accesses.

- **UI Model Functions**:  
  The patch includes fixes to functions that manage UI models, including `UI_Model_GetModelFromPath offset(0x2019670)`, `UIModel_CreateModelFromPath offset(0x2019080)`, and `UIModel_AllocateNode offset(0x2018DC0)`. These functions now properly validate the model path before processing it, ensuring that only valid paths are used to create or load models. Invalid paths are ignored, preventing errors when trying to load models or materials.

---
#### **Notetrack Fix**

**Problem**:  
The animation system may experience issues when handling notetrack data, leading to errors or undefined behavior when attempting to retrieve or manage the notetrack time associated with animations. Specifically, problems occur when the game attempts to retrieve the notetrack time using invalid or incorrect parameters, causing crashes or incorrect behavior.

**Solution**:  
This patch addresses these issues by improving the handling of notetrack time retrieval in the animation system. The solution involves adding a safe mechanism to handle notetrack retrieval errors and logging them for debugging purposes:

- **Notetrack Time Retrieval**:  
  The patch adds a modified version of the `XAnimGetNotetrackTime offset(0x2342100)` function. This function is responsible for retrieving the notetrack time associated with a given animation index and name. When an invalid or incorrect value is encountered, the function now handles the error gracefully by logging the error and returning a default value (`-1.0f`), which prevents further processing of invalid data.

- **Logging**:  
  The patch integrates logging functionality within the `XAnimGetNotetrackTime offset(0x2342100)` function to log the parameters of the failed notetrack retrieval attempt. This includes the animation index and the name length of the requested notetrack, providing valuable information for debugging.

- **Error Notification**:  
  In case of an error during the notetrack time retrieval, the patch triggers a notification with the message "error occurred while retrieving notetrack time." This ensures that errors are properly reported, making it easier to identify and fix issues related to notetrack time retrieval.

---
#### **Lobby UI Host Data Transmitted Fix**

**Problem**:  
In multiplayer lobbies, the `LobbyUI_HostDataTransmitted` function may fail to properly handle the transmission of host data, leading to issues with data synchronization or improper handling of lobby state during host transmissions. This can result in inconsistent or broken lobby behaviors, particularly when transmitting important host-related information.

**Solution**:  
This patch addresses the issue by modifying the behavior of the `LobbyUI_HostDataTransmitted offset(0x1F029F0)` function to ensure reliable transmission of host data and proper handling of lobby states. The solution includes the following:

- **Reliable Host Data Transmission**:  
  The patch provides a fixed implementation for the `LobbyUI_HostDataTransmitted offset(0x1F029F0)` function, ensuring that data transmission for host information is always handled correctly. The function now returns a fixed value of `true`, indicating that the host data transmission is always considered successful, preventing any failures during the process.

- **Simplified Handling for Lobby Type**:  
  The function accepts the `LobbyType` parameter, but the patch ensures that the logic for processing different lobby types is simplified. By always returning `true`, the patch bypasses any complex checks or potential failures, ensuring a smooth and uninterrupted host data transmission process in all scenarios.

- **Prevents Data Synchronization Issues**:  
  With this modification, the patch ensures that host data is consistently transmitted without the risk of synchronization issues that might otherwise occur if the transmission was unsuccessful or encountered errors.

---
#### **ExecLuaCMD Hook Protection (Prevent Remote Code Execution)**

**Problem**:  
The `ExecLuaCMD offset(0x1F04B20)` function, which is responsible for executing Lua commands, could be vulnerable to remote code execution (RCE) attacks. Exploiters could inject malicious Lua code into the game environment, leading to arbitrary command execution, unauthorized access, and potential system compromise. This vulnerability is particularly concerning in multiplayer scenarios where untrusted clients might attempt to execute Lua commands on the server.

**Solution**:  
This patch addresses the RCE vulnerability by hooking the `ExecLuaCMD offset(0x1F04B20)` function and sanitizing the Lua environment. The solution includes the following:

- **Sanitization of Lua Environment**:  
  The patch intercepts the `ExecLuaCMD offset(0x1F04B20)` function and ensures that no potentially dangerous or unauthorized Lua commands are executed. Instead of executing the Lua command, the function simply triggers a notification, signaling that the Lua environment has been sanitized. This effectively blocks any malicious commands from being executed.

- **Preventative Hooking**:  
  The `ExecLuaCMD_hook` function is hooked in place of the original `ExecLuaCMD offset(0x1F04B20)` function. By doing so, it prevents the execution of any Lua commands that could otherwise exploit the system. This is a proactive defense measure that eliminates the risk of Lua-based RCE.

- **Security Notification**:  
  When the hook is triggered, a security notification is sent, indicating that the Lua environment has been sanitized. This provides visibility into the protection mechanism and helps with monitoring for any potential exploit attempts.

---

### More Patches Coming  
This is just the first in a series of patches that will address various other vulnerabilities and crash exploits within **Call of Duty: Black Ops 3**. Future updates will further improve stability and security across multiplayer and lobby systems.

### How to Use  
To apply the patch, simply compile the tool and replace the existing message handling code with the updated functions. This will enable the additional checks and protection mechanisms described above, ensuring a more secure multiplayer experience.
