# TheNidavellirProject-Free  

### Overview  
The Nidavellir Project is a robust and free tool designed to fix numerous bugs and vulnerabilities in **Call of Duty: Black Ops 3**, particularly focusing on multiplayer and lobby systems. It addresses critical issues like invalid packet handling, buffer overflows, and crash exploits to enhance gameplay stability and security.  

### Features  
- Fixes improper message handling in lobby communication.  
- Mitigates vulnerabilities like buffer overflows and invalid memory accesses.  
- Prevents crashes caused by malformed or malicious packets.  
- Implements security checks to detect and stop exploit attempts.  
- Free and open-source for the community.  

### Patches  
Below is a detailed list of patches included in the tool, along with their fixes:  

1. **Host Heartbeat Handling**  
   - **File:** `lobby_msg_c::handle_host_heartbeat`  
   - **Fix:** Processes heartbeat messages securely by validating data like `heartbeatnum`, `lobbytype`, and `nomineelist`. Prevents overflows and ensures proper handling of incoming elements.  

2. **Join Request Validation**  
   - **File:** `lobby_msg_c::handle_join_request`  
   - **Fix:** Validates join request data such as lobby IDs, playlist information, and member count. Prevents overflow by capping `membercount` to 18 and ensures all parameters are correctly extracted and handled.  

3. **Demo State Inspection**  
   - **File:** `lobby_msg_c::handle_demo_state`  
   - **Fix:** Inspects demo state messages while validating parameters like `timescale` and `servertime`. Ensures valid bounds are respected to prevent out-of-bounds access and overflow issues.  

4. **Client Content Inspection**  
   - **File:** `lobby_msg_c::handle_client_content`  
   - **Fix:** Safeguards content by validating data masks, buffer sizes, and other parameters. Ensures no invalid packets exceed set thresholds, with added security measures to block malicious packets.  

5. **Instant Message Handling**  
   - **File:** `instant_message_c::dw_Instant_Dispatch_Message_h`  
   - **Fix:** This patch adds comprehensive security checks when handling instant messages, protecting against various message-based exploits. It includes the following protections:

     - **Empty or whitespace-only message check:**  
       This part of the patch ensures that messages containing only whitespace or no data at all are ignored. These types of messages could be used to flood the system with unnecessary traffic or test for vulnerabilities. If the message is empty or consists entirely of whitespace characters, it is discarded, preventing exploitation attempts that rely on invalid or malicious messages.

     - **Overflow prevention:**  
       The patch verifies that the message size (`message_size`) and the current read count (`msg.readcount`) are within valid bounds before processing the message. This prevents **buffer overflow attacks**, where an attacker might send a message that is too large to be processed safely, potentially leading to memory corruption or crashes.

     - **Known exploit prevention (message types '102', 'e', 'f'):**  
       The patch specifically looks for known message types that are commonly used in exploit attempts:

       - **Message Type '102':**  
         The message type '102' is typically used for exploit attempts in multiplayer games. The patch checks for this type and ensures that messages with the size of 102 bytes or 2 bytes are blocked. These sizes are associated with potential buffer overflow or denial-of-service (DoS) attacks. If a message of type '102' is detected, it is ignored to prevent these exploits.

       - **Message Type 'e' (Remote Cbuf Exploit):**  
         The message type 'e' is often used in **remote cbuf** exploits. A message of this type can be crafted to execute commands or trigger actions remotely, such as resetting stats or manipulating game data. An example of an exploit would be calling `dwInstantSendMessage(0, &targetXUID, 1, 'e', "resetStats\n", 11);`, which could execute a command like resetting player stats without proper authorization. This patch prevents this type of message from being processed, effectively blocking remote command execution and maintaining the integrity of the game environment.

       - **Message Type 'f' (Friend Message Exploit):**  
         The message type 'f' is used for **friend messages**, which are typically sent between players in the game. However, this message type can be exploited for **remote crashes** or **popup attacks**. Attackers could send malicious messages using this type to crash the client or trigger unwanted popups on the recipient's screen. The patch blocks messages of type 'f', preventing this type of exploit from being executed and protecting players from potential disruptions caused by malicious friend messages.

     - **Overflow protection in message parsing:**  
       The patch prevents buffer overflows during message parsing by ensuring that the data being read is within safe bounds. If a message exceeds a set size (e.g., 2048 bytes), it is rejected. This ensures that any attempt to send a message with excessive data that could trigger a crash or corrupt memory is blocked, providing additional protection against overflow exploits.

     - **Server response handling:**  
       The patch ensures that server responses, such as lobby information responses, are processed securely. It checks the integrity of the server response data and prevents any malicious interactions that could exploit vulnerabilities in the server-client communication.

