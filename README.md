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

#### **Crash Prevention for Malformed Packets (Instant Message Crash) in `dw_Instant_Dispatch_Message`**  

**Problem**:  
The crash occurs when malformed or empty messages are sent via the `dw_Instant_Dispatch_Message` function, which processes messages in multiplayer sessions. These messages can lead to crashes if they are empty, contain invalid data, or are sent in a way that bypasses size validation. Exploiters can send such malformed messages, causing buffer overflows or invalid memory accesses, which leads to crashes.

**Solution**:  
The patch prevents this issue by adding additional checks to the message processing flow:

- **Empty Message Handling**: The patch ensures that messages which are empty or contain only whitespace are ignored, preventing processing of invalid data.
  
- **Invalid Message Size Handling**: Messages that don't match the expected size or have an invalid read count are discarded. This prevents potential buffer overflows and memory corruption.

- **Message Type Validation**: The patch checks for specific message types and sizes, ensuring only valid messages are processed. Suspicious message types or incorrect sizes are ignored.

- **Command Buffer Exploit Prevention**: The patch specifically targets certain command buffer messages (`'e'` type) that could be exploited remotely and ensures they are ignored to avoid misuse.

- **Overflow Protection**: Additional checks are added to prevent buffer overflow scenarios when handling message data. If an overflow is detected, the message is discarded to prevent a crash.

---

### More Patches Coming  
This is just the first in a series of patches that will address various other vulnerabilities and crash exploits within **Call of Duty: Black Ops 3**. Future updates will further improve stability and security across multiplayer and lobby systems.

### How to Use  
To apply the patch, simply compile the tool and replace the existing message handling code with the updated functions. This will enable the additional checks and protection mechanisms described above, ensuring a more secure multiplayer experience.
