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

#### **Crash Prevention for Malformed Packets (Instant Message Crash)**  
**Problem**:  
The crash is caused by malformed or empty messages being sent via the `dw_Instant_Dispatch_Message` function, which processes messages in multiplayer sessions. These messages can lead to crashes if they are empty, contain invalid data, or are sent in a way that bypasses size validation. Specifically, the function `send_instant_crash` used by exploiters can send a message with no valid content, potentially leading to buffer overflows or invalid memory accesses.

**Solution**:  
To prevent this, the patch modifies the way messages are handled before they are dispatched. Key steps include:

1. **Empty Message Handling**:  
   The patch checks if the message is empty or contains only whitespace. If this is the case, the message is ignored.
   
   ```cpp
   if (message == nullptr || message_size == 0 || std::all_of(message, message + message_size, [](unsigned char c) { return std::isspace(c); }))
   {
       return true; // Ignored empty or whitespace-only message
   }
