# SIEM TOOLS DEPLOYMENT FOR THREAT AND ACTIVE RESPONSE

### OBJECTIVE
In an attempt to gain a deeper understanding of how Endpoint devices on an organization's network are effectively secured (as part of my SOC analyst training), I took on the challenge of learning how to use SIEM tools like Wazuh and Splunk with Sysmon to visualize all security events on endpoint devices, making it a handy Host intrusion detection system (HIDS) to easily detect threats, monitor file's integrity and vulnerabilitie. I will also be integrating Wazuh with Virustotal (an open source tool for scanning files for viruses) with a Python script to automate the deletion of any malicious files that manage to bypass Windows security

### SKILLS LEARNED
Throughout this project, I’ve gained hands-on experience and acquired in-depth technical knowledge in deploying and managing Wazuh as a Host Intrusion Detection System (HIDS), tailored to meet organizational security needs. Below are the key competencies I’ve developed:
##### Wazuh & OSSEC Configuration
* Mastered the deployment and configuration of Wazuh Manager to generate targeted security alerts based on organizational priorities.
* Proficient in configuring the OSSEC agent for monitoring diverse security events across endpoints.

##### Event Analysis & Threat Detection
* Developed expertise in reading and interpreting Wazuh event logs to identify Indicators of Compromise (IOCs).
* Configured index rules to prioritize and filter events of interest for faster incident response.
* Enhanced ability to detect network anomalies and execute timely, effective mitigation strategies.
##### Automation & Scripting
* Automated key security processes to improve operational efficiency and reduce human error.
* Created custom detection scripts with Python, including tools to identify and neutralize threats like Virustotal, strengthening the SOC’s defense against advanced attacks.
##### Infrastructure & OS Integration
* Gained practical experience in configuring and managing security infrastructure across on-premises and cloud environments, supporting resilient SOC operations.
* Improved proficiency in integrating and managing multiple operating systems within the SOC, ensuring a unified and secure posture.
* Skilled in firewall configuration, enabling or restricting traffic on specific ports to enhance network security.



### TOOLS USED
![Google Cloud](https://img.shields.io/badge/Google%20Cloud-Infrastructure-blue?logo=google-cloud&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-Windows%20Monitoring-important?logo=windows&logoColor=white)
![Wazuh SIEM](https://img.shields.io/badge/Wazuh%20SIEM-Open%20Source%20Security-brightgreen?logo=wazuh&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Threat%20Analysis-red?logo=virustotal&logoColor=white)



### STEPS
Below are the steps I took to complete this project:
##### Configuring my network interface on Google Cloud
* I create a network interface on Google Cloud
* I create a VM instance for Windows, Ubuntu, and Kali OS.
##### deployment of Wazuh
* I deploy Wazuh on an Ubuntu machine
* I install Sysmon on my Windows machine
* I configure the server file
* I added a window agent where I configure the Ossec file to collect log from Sysmon
* I configure the OSSEC file to monitor file integrity in some directory on my Windows machine.
##### Automating threat detection
* I installed Python automation scripts on a Windows machine, where I placed it in the ossec-agent/bin directory
* I added a script to the Wazuh server config file with VirusTotal API
* I downloaded a malicious file to test the integration.
##### Attacking my Windows machine to see how the logs will be collected. 
* I created a random file and modified it to see how Wazuh will log it with "WHODATA" capability
* I launched an RDP brute force attack using Hydra on my Kali machine to see how Wazuh threat detection logs the events.
Click the Wazuh icon below to view the Wazuh images to see how the logs were captured:
  
### Wazuh events log:
![Wazuh SIEM](https://img.shields.io/badge/Wazuh%20SIEM-EVENTS%20LOGS%20SCREENSHOT-brightgreen?logo=wazuh&logoColor=white)
