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
#### **Notetrack Time Fix**

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
In multiplayer lobbies, the `LobbyUI_HostDataTransmitted offset(0x1F029F0)` function may fail to properly handle the transmission of host data, leading to issues with data synchronization or improper handling of lobby state during host transmissions. This can result in inconsistent or broken lobby behaviors, particularly when transmitting important host-related information.

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
#### **Lua_CmdParseArgs Hook Protection (Prevent Remote Code Execution)**

**Problem**:  
The `Lua_CmdParseArgs offset(0x1F054E0)` function is responsible for parsing arguments passed to Lua commands. If exploited, attackers could craft malicious arguments to execute arbitrary code within the Lua environment, leading to a potential remote code execution (RCE) vulnerability. This poses a significant security risk in multiplayer environments, where untrusted clients may attempt to execute unauthorized commands on the server.

**Solution**:  
This patch mitigates the RCE vulnerability by hooking the `Lua_CmdParseArgs offset(0x1F054E0)` function and preventing the parsing of potentially harmful arguments. The solution includes the following:

- **Argument Sanitization**:  
  The patch intercepts the `Lua_CmdParseArgs offset(0x1F054E0)` function, preventing the parsing of any potentially dangerous or crafted arguments. Instead of proceeding with parsing, the function triggers a security notification, signaling that an RCE attempt has been detected and blocked.

- **Preventative Hooking**:  
  The `Lua_CmdParseArgs_hook` function is hooked into place of the original `Lua_CmdParseArgs offset(0x1F054E0)` function, ensuring that no malicious arguments are parsed and executed. This proactive defense helps eliminate the possibility of RCE exploits through crafted arguments.

- **Security Notification**:  
  Upon triggering the hook, a security notification is displayed, indicating that an RCE attempt has been prevented. This serves as a real-time alert, providing insight into potential exploit attempts and enhancing the game's overall security posture.

---
#### **Lobby Disconnect Protection in theLobbyVM_OnDisconnect offset(0x1EEFEC0)**

**Problem**:  
The function `LobbyVM_OnDisconnect offset(0x1EEFEC0)` is responsible for handling client disconnections in the lobby, including disconnections caused by various reasons, such as kicks or drops. Malicious users could attempt to manipulate this function to avoid detection or prevent proper logging of their disconnection reasons.

**Solution**:  
This patch hooks into the `LobbyVM_OnDisconnect offset(0x1EEFEC0)` function to log and notify about client disconnections. When a client disconnects, the patch identifies the disconnection reason and logs it with the client's identity. It helps prevent bypassing of disconnection messages and ensures proper logging of malicious or suspicious actions.

- **Enhanced Logging and Identification**:  
  The patch provides a more detailed log for disconnections, including the XUID and identity of the client disconnecting. It categorizes the disconnection reason using an enumerated type `LobbyDisconnectClient`, which includes values such as `KICK`, `DROP`, and `HOSTRELOAD`. This provides a clearer understanding of why a client disconnected.

- **Detailed Disconnection Handling**:  
  The patch ensures that each disconnection is mapped to a clear reason using the `clientToStringMap`, which maps each disconnection type to a string (e.g., "KICK", "DROP", "BADDLC"). This helps identify and track disconnections more accurately, preventing potential manipulation of disconnect reasons.

- **Security and Monitoring**:  
  By logging the reason for each disconnection and notifying the system when a kick or drop occurs, the patch strengthens monitoring and security by making it harder for attackers to hide their actions. It also ensures that any unusual or unexpected disconnection events are flagged and logged.

---
#### **MSG_ReadByte offset(0x2155450) Hook Protection**

**Problem**:  
The function `sub_2155450`, also known as `MSG_ReadByte offset(0x2155450)`, is used to read a byte from a message buffer. In certain cases, attackers could manipulate the message processing to bypass or exploit buffer reading, leading to unexpected behavior, data corruption, or crashes.

**Solution**:  
This patch hooks into the `MSG_ReadByte offset(0x2155450)` function and modifies its behavior to add proper boundary checks and ensure the message processing is robust. The patch ensures that the reading of bytes is done safely by checking whether the current reading position is within the bounds of the allocated buffer.

- **Boundary Check**:  
  The patch checks that the `v3` (current reading position) does not exceed the bounds of the buffer. If the reading position is out of bounds, the function will set a flag and return early to prevent accessing invalid memory. This helps prevent buffer overflows or accessing memory that shouldn't be accessed.

- **Safe Byte Reading**:  
  The patch ensures that only valid bytes are read by verifying that the current position is within the valid range before attempting to access memory. If the position is valid, the function reads the byte and updates the reading position (`v5`) accordingly.

- **Early Exit on Invalid Read**:  
  If the function detects an invalid read (e.g., reading from an out-of-bounds location), it will immediately return `0`, signaling that the read operation was unsuccessful. This early exit prevents unintended memory access and improves stability.

---
#### **sub_2C3D960 Hook Protection**

**Problem**:  
The `sub_2C3D960` function performs complex memory copying operations, including handling overlapping memory and managing different sizes of data. If improperly handled, this function could lead to memory corruption, buffer overflows, or unintended data manipulation, especially when dealing with unaligned memory or large data blocks.

**Solution**:  
This patch modifies the `sub_2C3D960` function to improve memory safety and prevent potential exploits such as buffer overflows and data corruption.

- **Boundary Check & Safe Memory Copying**:  
  The patch checks whether memory copying operations might overlap and ensures that copying does not go beyond the bounds of the allocated memory. If the copying operation is small (less than or equal to `0x10`), it uses a direct approach. Otherwise, it handles more complex cases, such as overlapping memory, in a way that ensures no invalid memory access occurs.

- **Handling Unaligned Memory**:  
  If the memory addresses are unaligned (not divisible by 8), the patch ensures that smaller chunks of memory are copied correctly. This includes manually handling byte, word, and dword copies and ensuring that memory is copied in a manner that avoids misalignment issues.

- **Optimized Memory Copying**:  
  For larger memory regions (greater than or equal to `0x1000`), the patch uses `memcpy` to efficiently handle large blocks of data. It ensures that memory is copied in blocks of 4KB or smaller, avoiding unnecessary overhead.

- **Flag-Based Copying Behavior**:  
  The patch introduces a flag (`dword_1A8A4F94`) to control whether the copy should be performed using `memcpy` or through the manual, byte-wise copying approach. If the flag indicates a specific condition, `memcpy` is used to improve performance and safety.

- **Safe Data Handling**:  
  The patch also ensures that the function safely handles data of different sizes (e.g., single bytes, short words, dwords) by adjusting the copy operation based on the size of the data being copied.

---
#### **Steam_AuthTicketHandle offset(0x1EB4780) Protection**

**Problem**:  
The `Steam_AuthTicketHandle offset(0x1EB4780)` function processes authentication tickets, which are essential for verifying the legitimacy of players attempting to connect to the server. Without proper validation, attackers could send malicious or malformed messages, potentially leading to exploits such as unauthorized access or server crashes.

**Solution**:  
This patch adds additional validation to the `Steam_AuthTicketHandle offset(0x1EB4780)` function to prevent unauthorized access and handle potentially malicious tickets more securely.

- **Message Size Check**:  
  The patch ensures that the size of the authentication message is valid by checking if it is greater than 1024 bytes, with a specific index condition (`index - 21 == 0`). If the size exceeds this threshold, the message is flagged as potentially malicious, and the processing is halted.

- **Protection Notification**:  
  If a suspicious or malformed authentication ticket is detected, the patch notifies the system that the protection mechanism has triggered, providing details of the sender.

- **Fallback to Original Function**:  
  If the ticket passes the validation checks, the function proceeds to call the original `Steam_AuthTicketHandle offset(0x1EB4780)` function to process the ticket normally.

---
#### **sub_1E91820 Patch (Demonware / Client Party Info / Player Presence)**

**Problem**:  
The `sub_1E91820` function appears to be involved in handling player presence requests, which could include retrieving or interacting with party or session data. Improper handling of these requests may lead to vulnerabilities, such as unauthorized access to presence or party information, or even manipulation of the client party state.

**Solution**:  
This patch modifies the `sub_1E91820` function to prevent any operations related to player presence, party information, or Demonware interaction. By neutralizing this function, it avoids potential exploits related to unauthorized manipulation of player presence or client party states.

- **No-Operation (NOP) Implementation**:  
  The function is explicitly modified to return immediately without performing any action (`return;`), ensuring that no data related to player presence or party interactions is processed or manipulated. This eliminates the potential for unwanted behavior or vulnerabilities.

- **Security and Stability**:  
  By disabling this function, the patch safeguards against exploits involving player presence requests, party data retrieval, or interactions with Demonware systems. This can prevent players from gaining unauthorized access to sensitive information or tampering with the client party status.

---

#### **Lobby Message Handling Patches (Overflow/Underflow Prevention)**

**Problem**:  
The functions related to printing debug messages in the lobby message handling can be vulnerable to crashes caused by buffer overflow or underflow issues. Exploits targeting these functions could cause instability and security risks in the game.

**Solution**:  
The following patches have been implemented to mitigate potential overflow and underflow issues within the lobby message handling functions, providing added protection against crash attempts:

1. **LobbyMsgRW_PrintDebugMessage offset(0x1EF6B80) Patch (Overflow Prevention)**:
   - **Purpose**: This function is used for printing debug messages within the lobby message handling system.
   - **Issue**: An unchecked overflow condition can lead to crashes, especially when invalid or malicious data is passed.
   - **Fix**: This patch intercepts the function and checks for potential overflows. If an overflow attempt is detected, the function immediately returns, logging the event and notifying that the overflow attempt has been prevented.
     - The function returns `true` to ensure that the process doesn't continue with potentially damaging data.
     - A notification message `attempt detected and prevented` is logged for security monitoring.

2. **LobbyMsgRW_PrintMessage offset(0x1EF6E40) Patch (Underflow Prevention)**:
   - **Purpose**: Similar to the first patch, this function handles the printing of messages within the lobby system, but in this case, it deals with underflow conditions.
   - **Issue**: An underflow could occur if the message length or buffer size is improperly calculated, potentially leading to instability.
   - **Fix**: The patch intercepts the call to prevent any underflow issues. If such an issue is detected, the function immediately returns and logs the event with a notification message.
     - The message `attempt detected and prevented` is logged to provide security visibility.
     - The function returns `true` to halt any further processing of potentially damaging data.

- **Security and Stability**:
  - These patches protect the game from potential crashes caused by malicious data and buffer overflow/underflow attempts.
  - By logging and preventing such issues, the patches improve the stability of the game, reducing the risk of unexpected crashes.

---

### LobbyMSG Inspect StateGame Function

The `LobbyMSG Inspect StateGame` function ensures the integrity and security of the state game message package by applying multiple validation checks. These checks prevent potential crashes, invalid data processing, and malicious exploit attempts.

#### Key Fixes and Validations:
- **Overflow and Underflow Protections:**
  - Validates array sizes (e.g., `clientlist`, `votes`) to ensure they do not exceed predefined limits:
    - `clientlist` is limited to 18 elements.
    - `votes` is capped at 216 elements.
  - If these limits are exceeded, the function triggers overflow protection and prevents further processing.
  
- **Packet Validation:**
  - Ensures proper packing of individual fields in the state game message:
    - Integer and string fields (e.g., `serverstatus`, `gametype`, `matchhashlow`, `status`) are validated.
    - Array fields (e.g., `clientlist`, `votes`) are validated to ensure correct packing of elements.
  
- **Handling Invalid Packets:**
  - If any field is missing or contains invalid data, the function triggers a security notification and returns an error code, stopping further processing of the malicious packet.
  
- **Specific Fixes:**
  - **Overflow Protection:** Prevents buffer overflow in fields such as `votecount` and `plistentries`.
  - **Invalid Packet Detection:** Invalid data is rejected, and a security notification is triggered.
  - **Client and Vote Processing:** Each client and vote entry is validated to ensure the data is packed correctly.

#### Example Error Codes:
- **21**: Invalid packet detected.
- **22**: Overflow protection triggered.
- **5**: Bad packet due to missing or invalid data.
- **7**: Bad packet due to invalid vote data.
- **26**: Crash attempt via vote count overflow.
- **28**: Crash attempt due to excess elements in `votes` array.
- **37**: Crash attempt due to vote count buffer overflow.
- **39**: Crash attempt due to excess elements in `clientlist` array.
  
---

### LobbyMSG Inspect StatePrivate Function

The `LobbyMSG Inspect StatePrivate` function ensures that the `lobbyMsg` received for a private lobby state is properly validated. It performs a series of integrity checks on the message to detect and prevent invalid packets, overflow attempts, and malicious exploitations.

#### Key Fixes and Validations:
- **Packet Validation:**
  - Each field in the lobby message is validated for correctness using functions like `LobbyMsgRW_PackageInt`, `LobbyMsgRW_PackageUChar`, `LobbyMsgRW_PackageString`, and `LobbyMsgRW_PackageXuid`.
  - If any field is missing or invalid, the function halts further processing and returns a specific error code.

- **Overflow and Underflow Protections:**
  - **Client List:** Ensures the number of clients does not exceed 18 (`clientcount`), preventing any potential overflow or underflow attempts.
  - If the `clientcount` exceeds the limit, an underflow error is triggered, stopping further packet processing.
  
- **Nominee List Handling:**
  - A separate check ensures that the `nomineelist` field does not contain more than 18 elements, preventing overflow attempts by exploiting the number of elements.

- **Specific Fixes:**
  - **Bad Packet Detection:** Invalid or corrupt packets are immediately rejected, and the function triggers a security notification.
  - **Element Checks:** The function uses `LobbyMsgRW_PackageElement` to iterate through elements in `clientlist` and `nomineelist`, ensuring that each element is correctly packed.
  - **XUID and Address Data:** XUIDs and other client-specific data are validated, ensuring integrity and security.
  - **Overflow and Buffer Exploits:** The function detects attempts to exploit buffer overflows, protecting against common attack vectors like buffer overflow or element read-only exploits.

#### Example Error Codes:
- **1**: Bad packet detected (general invalid packet).
- **2**: Client count exceeds allowed limit (overflow protection triggered).
- **3**: Bad packet detected (specific to fields like `migratebits` or `lasthosttimems`).
- **4**: General bad packet (after all validations).
- **101**: Invalid packet in client data (during iteration of `clientlist`).
- **102**: Exploit attempt detected via buffer overflow or element read-only exploit.
- **103**: Exploit attempt detected via `nomineelist` overflow.

---

### LobbyMSG Inspect ClientContent Function

The `LobbyMSG Inspect ClientContent` function validates the content of the lobby message specifically related to client information. It checks for invalid packets, ensures the integrity of various fields, and prevents exploits such as large buffer sizes or invalid session and game modes.

#### Key Fixes and Validations:
- **Packet Validation:**
  - The function uses `LobbyMsgRW_PackageUInt`, `LobbyMsgRW_PackageInt`, `LobbyMsgRW_PackageXuid`, `LobbyMsgRW_PackageUShort`, `LobbyMsgRW_PackageGlob`, and `LobbyMsgRW_PackageUChar` to validate the key fields of the lobby message:
    - `datamask`: Ensures proper data masking.
    - `lobbytype`: Validates the lobby type.
    - `clientxuid`: Verifies the XUID of the client.
    - `buffersize`: Checks the size of the buffer.
    - `buffer`: Ensures that the buffer data is within the expected size.
    - `sessionmode`: Ensures the session mode is valid.
    - `gamemode`: Ensures the game mode is valid.

- **Range Checks:**
  - **Client XUID Validation:** Ensures that the `clientxuid` field does not exceed a specified maximum value (175,000).
  - **Buffer Size Validation:** Ensures that the `buffersize` does not exceed the maximum allowed value (175,000), which prevents any malicious attempts to overflow the buffer.

- **Bad Packet Detection:**
  - If any of the validation checks fail or if the fields exceed the allowed limits, the packet is considered invalid and rejected.
  - The function triggers a security notification (`notify::security`) to alert that an invalid packet was detected.

#### Example Error Codes:
- **1**: Invalid packet detected (any field validation failure, such as exceeding the buffer size or XUID range).

---

### LobbyMSG Inspect DemoState Function

The `LobbyMSG Inspect DemoState` function is responsible for validating and inspecting the demo state within the lobby message. It ensures that all required fields are properly packed, checks for overflow conditions, and prevents invalid or exploitative packets from being processed.

#### Key Fixes and Validations:
- **Packet Validation:**
  - The function uses `LobbyMsgRW_PackageInt` and `LobbyMsgRW_PackageBool` to validate the following fields within the demo state:
    - `lobbytype`: Ensures that the lobby type is valid.
    - `paused`: Checks if the demo is paused.
    - `servertime`: Verifies the server time.
    - `timescale`: Checks the time scale value.
    - `client`: Ensures the client field is correctly populated.
    - `kframeindex`: Validates the current keyframe index.
    - `lstjumpedkframe`: Ensures the last jumped keyframe is valid.
    - `kframejumpcount`: Verifies the count of keyframe jumps.
    - `lstkframetime`: Checks the last keyframe time.

- **Overflow Checks:**
  - **Timescale Validation:** Ensures that the `timescale` field does not exceed a specified value of `10`, preventing excessive time manipulation.
  - **Server Time Validation:** Ensures that the `servertime` field is not negative.
  - **Client Validation:** Ensures that the `client` field is not negative, which could indicate a malformed packet.

- **Bad Packet Detection:**
  - If any of the validation checks fail, the packet is considered invalid and rejected.
  - The function triggers an overflow attempt notification (`notify::overflow`) to alert that an invalid packet was detected.

#### Example Error Codes:
- **1**: Invalid packet detected (failure in packet validation or overflow attempts).

---

### LobbyMSG Inspect JoinRequest Function

The `LobbyMSG Inspect JoinRequest` function processes and validates a join request message. It checks the contents of the message for various data fields, ensuring that they are correctly packed and within valid ranges. This function also includes overflow protection for certain fields.

#### Key Data Fields Processed:
- **targetlobby:** Identifies the target lobby for the join request.
- **sourcelobby:** Specifies the source lobby from which the join request originates.
- **jointype:** Defines the type of the join request (e.g., invitation, direct join).
- **probedxuid:** The XUID of the client probing for the join request.
- **playlistid:** The ID of the playlist being requested for joining.
- **playlistver:** The version of the playlist being requested.
- **ffotdver:** The version of the "Feature of the Day" content.
- **networkmode:** Specifies the network mode for the join request.
- **netchecksum:** A checksum for the network data.
- **protocol:** The protocol version used in the join request.
- **changelist:** The changelist version for the content being joined.
- **pingband:** A measure of the network ping band.
- **dlcbits:** Represents downloadable content bits in the request.
- **joinnonce:** A unique identifier for the join request, preventing replay attacks.
- **chunkStatus:** An array representing the status of each content chunk in the join request.
- **isStarterPack:** Indicates if the client has the starter pack for the game.
- **password:** A password for joining a protected lobby.
- **memberCount:** The current number of members in the lobby.

#### Overflow Protection:
- **memberCount Check:** The function ensures that the `memberCount` does not exceed a threshold of `18` to prevent overloading the lobby. If this limit is exceeded, an overflow attempt is detected and prevented.
- **Error Handling:** If any field fails to validate or if any required data is missing, the function returns an error (`true`), indicating a failed join request.

#### Example Error Handling:
- **Overflow Attempt:** If the `memberCount` exceeds `17`, a notification (`notify::overflow`) is triggered to prevent the attempt.
- **Invalid Data:** If any of the data fields are improperly packed or fail validation, the function returns `true` to indicate an invalid packet.

#### Example Error Codes:
- **1**: Invalid or failed join request (packet validation or overflow attempt).
- **0**: Successful join request (all checks passed).

---

### LobbyMSG Inspect HostHeartbBeat Function

The `LobbyMSG Inspect HostHeartbBeat` function processes the heartbeat message from the host in the lobby. It validates the message by checking and extracting several data fields related to the host's state and the list of nominated players. This function also includes checks to ensure that the number of elements (nominated players) does not exceed a set limit.

#### Key Data Fields Processed:
- **heartbeatnum:** The number of the current heartbeat message.
- **lobbytype:** The type of lobby for the heartbeat message.
- **lasthosttimems:** The timestamp of the last host's heartbeat, measured in milliseconds.
- **nomineelist:** The list of nominated players for the current lobby. This list is capped to a maximum of 18 players.

#### Logic:
- The function starts by extracting the **heartbeatnum**, **lobbytype**, and **lasthosttimems** fields from the heartbeat message.
- Then it processes the **nomineelist**, which contains XUIDs for nominated players. It checks each element in the list and extracts the **xuid** for each player. The list is limited to 18 players. If more than 18 elements are found, an error code (`101`) is returned to indicate an overflow.

#### Overflow Protection:
- **Nominee List Limit:** The function ensures that the number of nominated players does not exceed 18. If there are more than 18 players in the list, it returns an error (`101`).
- **Error Handling:** If any of the fields fail validation or if the nominee list exceeds the allowed size, the function returns `true` to indicate an invalid message.

#### Example Error Codes:
- **1**: Invalid message or failed validation.
- **101**: Overflow attempt detected (more than 18 nominated players).
- **0**: Successful processing of the heartbeat message.

---

### More Patches Coming  
This is just the first in a series of patches that will address various other vulnerabilities and crash exploits within **Call of Duty: Black Ops 3**. Future updates will further improve stability and security across multiplayer and lobby systems.

## Spoofing

The **Spoofing** category involves modifying or "spoofing" network-related information to impersonate or hide the true identity of the sender. This can include spoofing security identifiers, IP addresses, and other critical network parameters. The functions in this category modify lobby-related data to simulate different network configurations, often for testing or exploiting purposes.

### package_info_response_lobby_h Function

The `package_info_response_lobby_h` function is responsible for spoofing certain network details in the `InfoResponseLobby` structure before the message is sent. It overrides security-related information, IP addresses, and other parameters to make the response appear as though it is coming from a different or spoofed source.

#### Key Actions:
1. **Security ID and Key Spoofing**:
   - The function replaces the original security ID (`secId`) and security key (`secKey`) in the `InfoResponseLobby` structure with the spoofed values from the configuration.
   
2. **IP Address Spoofing**:
   - The function modifies the IP address (`serializedAdr.xnaddr.addrBuff.ab.ipv4.octets`) to a spoofed IP address, making it appear as though the response is coming from a different remote address.

3. **Port Configuration**:
   - The port is set to `1`, further disguising the actual network communication details.

4. **Hostname and UGC Name Spoofing**:
   - The function changes the `hostName` and `ugcName` fields to preset values, "Nidavellir > u" and "^5Nidavellir", respectively, to simulate different lobby names.

5. **Lobby Parameters**:
   - The `ugcVersion` is set to `999`, and network and main mode values are modified to represent invalid or spoofed configurations.

#### Example:
- **Security ID and Key**: Replaces the real security identifiers with values from the configuration (`configs.spoofed_security_id` and `configs.spoofed_security_key`).
- **IP Address**: Spoofs the sender's IP address (`configs.spoofed_ip_address`) and sets a fake port.
- **Lobby Name**: Changes the lobby name to "Nidavellir > u" and the UGC name to "^5Nidavellir".

#### Function Flow:
- The function checks if the `packageType` in `lobby_msg` is `PACKAGE_TYPE_WRITE`.
- If true, it performs the spoofing operations, such as modifying the security ID, key, IP address, and other parameters.
- Finally, it calls `Msg_InfoResponsePackage` to send the modified message.

#### Code Example:

```cpp
const static auto Msg_InfoResponsePackage = reinterpret_cast<bool(*)(structures::InfoResponseLobby * info, structures::LobbyMsg * lobbyMsg)>(offsets::get_aslr_address(0x1EDAFC0));

bool __fastcall package_info_response_lobby_h(structures::InfoResponseLobby* lobby, structures::LobbyMsg* lobby_msg)
{
    if (lobby_msg->packageType == structures::PACKAGE_TYPE_WRITE)
    {
        for (int i = 0; i < 8; ++i)
        {
            lobby->secId.ab[i] = configs.spoofed_security_id[i];
        }

        for (int i = 0; i < 16; ++i)
        {
            lobby->secKey.ab[i] = configs.spoofed_security_key[i];
        }

        for (int i = 0; i < 4; ++i)
        {
            lobby->serializedAdr.xnaddr.addrBuff.ab.ipv4.octets[i] = configs.spoofed_ip_address[i];
        }

        lobby->serializedAdr.xnaddr.addrBuff.ab.port = 1;

        strncpy(lobby->hostName, "Nidavellir > u", 32);
        strncpy(lobby->ugcName, "^5Nidavellir", 32);

        lobby->ugcVersion = 999;
        lobby->lobbyParams.networkMode = structures::LOBBY_NETWORKMODE_UNKNOWN;
        lobby->lobbyParams.mainMode = structures::LOBBY_MAINMODE_INVALID;
    }

    return Msg_InfoResponsePackage(lobby, lobby_msg);
}
