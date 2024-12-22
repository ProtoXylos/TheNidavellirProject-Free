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
   - **File:** `lobby_msg_c::inspect_demo_state`  
   - **Fix:** Inspects demo state messages while validating parameters like `timescale` and `servertime`. Ensures valid bounds are respected to prevent out-of-bounds access and overflow issues.  

4. **Client Content Inspection**  
   - **File:** `lobby_msg_c::inspect_client_content`  
   - **Fix:** Safeguards content by validating data masks, buffer sizes, and other parameters. Ensures no invalid packets exceed set thresholds, with added security measures to block malicious packets.  

*(Add more patches in this format as you go.)*  

### Installation  
1. Clone this repository:  
   ```bash
   git clone https://github.com/YourUsername/TheNidavellirProject-Free.git
