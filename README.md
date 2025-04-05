# SOAR-EDR Project

## Objective

The SOAR-EDR project aimed to configure a SOAR-EDR environment with Tines and LimaCharlie to automate detection and response. Primary focus was to create custom detection and response rules to detect and respond to known malware and to prompt the user if they wanted to isolate the machine, if the answer was yes Tines would automatically isolate the machine. This hands-on experience was designed to strengthen understanding of SOAR and EDR tools, building playbooks and monitoring endpoint telemetry.

### Skills Learned

- Advanced understanding of workflow and playbook design.
- Proficiency in analyzing and interpreting network logs.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of EDR.
- strengthened knowledge of SOAR

### Tools Used

- Tines (SOAR platform) to receive information from the EDR and automate response.
- LimaCharlie (EDR platform) to monitor devices connected to the network.
- VirusTotal used to perform OSINT on potentially malicious software / IPs.
- Slack to create an alert dashboard in which alerts were sent to after detection.
- Vultr used to create a virtual server in the cloud for EDR

## Steps
- First screenshot is a draw.io diagram of the workflow of the entire SOAR-EDR project, consisting of software and tools used to send messages, detect alerts and responsed accordingly
![Screenshot 2025-04-03 235853](https://github.com/user-attachments/assets/b28fa6a8-4897-4100-85d8-ccfe53618d96)
- Next four screenshots are of LimaCharlie after the virtual server in the cloud was connected, and shows: the file system, processes, network and timeline of events that occured on the virtual server.
![Screenshot 2025-04-03 235531](https://github.com/user-attachments/assets/67993711-ff55-496d-975a-cee076ea62b9)![Screenshot 2025-04-03 235600](https://github.com/user-attachments/assets/c20dd5b2-2971-468f-ba5a-1b1f2be603e9)![Screenshot 2025-04-03 235614](https://github.com/user-attachments/assets/96ca3e24-7630-444f-86b2-cda6fb593f6a)![Screenshot 2025-04-03 235745](https://github.com/user-attachments/assets/6fd919f6-1d95-4417-8d03-48b32c1c3a69)
- Next two screenshots are the custom Detection and Response rules in LimaCharlie, with the aim to detect the malicious executable file 'laZagne.exe' by file path, command line and hash value. The response rule has the aim to generate a report (action:report) about the specific HackTool laZagne.exe that is labelled using the MITRE ATT&CK framework attack.credential.access - relates to techinques that are used to steal credentials.
![Screenshot 2025-04-04 134239](https://github.com/user-attachments/assets/d5366ebc-a570-4cc8-9136-68337636c3c6)![Screenshot 2025-04-04 134245](https://github.com/user-attachments/assets/d1645d4a-1436-420c-a317-8324a211d972)
- Screenshot shows LimaCharlie Detections tab after 'laZagne.exe' was executed once the custom detection and response rules were created - LimaCharlie successfully detected the process.
![Screenshot 2025-04-04 134757](https://github.com/user-attachments/assets/30710736-43a5-427a-afe7-adf49a68bb1c)
- Screenshot shows the completed playbook that was created in Tines. Consists of a webhook: to retrieve detections, detections are then forwarded to Slack in the alert dashboard, forwarded via email and finally forwarded to the user prompt. User prompt poses the question whether the user wishes to isolate the machine or not. If user decides not to isolate the machine, the machine will not be isolated and a message is forwarded to Slack to relay the information that the machine was not isolated. If user decides to isolate the machine, the machine is identified using the Sensor ID and machine is automatically isolated using LimaCharlie, a message is also relayed to Slack, regarding the isolation status.
![Screenshot 2025-04-04 161544](https://github.com/user-attachments/assets/dd6b7dbc-d16b-4c6e-89be-9f0123d183c9)
- First screenshot shows the message sent to the alert dashboard in Slack, containing the information that was detected in the webhook. Second screenshot shows the same information sent via email.
![Screenshot 2025-04-04 152933](https://github.com/user-attachments/assets/73713295-e02a-45e8-8563-2d902fdc5051)![Screenshot 2025-04-04 153702](https://github.com/user-attachments/assets/cad3a7e8-d1cc-4ffd-89ba-a5aaf3c900ff)
- Screenshot shows the user prompt generated with the detection information and gives the user a choice to isolate the machine or not.
![Screenshot 2025-04-04 153950](https://github.com/user-attachments/assets/44448be5-d25f-4671-a14d-ff04cb75e5ed)
- First screenshot shows the message sent to the alert dashboard in Slack if the user chooses not to isolate the machine. Second screenshot shows the message sent to Slack if the user decides to isolate the machine.
![Screenshot 2025-04-04 154741](https://github.com/user-attachments/assets/0fdfe349-7c4e-4ecf-bd43-f116c121fed2)
![Screenshot 2025-04-04 160859](https://github.com/user-attachments/assets/e931f68d-9e63-4e27-b2fd-abdedee9cf87)
- Two screenshots that show the network access of the machine in LimaCharlie before isolation and after isolation.
![Screenshot 2025-04-04 155820](https://github.com/user-attachments/assets/3e729ac9-2d62-4240-86b4-fee98e27a452)
![Screenshot 2025-04-04 155906](https://github.com/user-attachments/assets/5922e230-79b2-46d2-884f-0e1cf2568257)
- Final screenshot is a powershell window with the command ran 'ping google.com -t' to endlessly ping google.com. Screenshot shows successfull pings towards google.com that receive a reply, before machine was isolated, the powershell window then shows general failure from the pings which shows that the machine was successfully isolated.
![Screenshot 2025-04-04 160122](https://github.com/user-attachments/assets/77db4b62-0194-4af8-86a9-f3bde8c789f3)













