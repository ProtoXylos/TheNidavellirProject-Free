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

### More Patches Coming  
This is just the first in a series of patches that will address various other vulnerabilities and crash exploits within **Call of Duty: Black Ops 3**. Future updates will further improve stability and security across multiplayer and lobby systems.

### How to Use  
To apply the patch, simply compile the tool and replace the existing message handling code with the updated functions. This will enable the additional checks and protection mechanisms described above, ensuring a more secure multiplayer experience.
