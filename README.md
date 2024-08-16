# Supercharging Your Security Operations: Integrating MISP with Wazuh for Enhanced Threat Intelligence - IP Threat Intel





Installation Process: Getting Started with the Integration

Setting up the integration between MISP and Wazuh requires several steps, including installing dependencies, configuring your environment, and setting up the custom scripts. Here’s how to get started:

1. Install MISP

Follow the official MISP installation guide to set up MISP on your server. MISP can be installed on various Linux distributions, including Ubuntu and CentOS. Ensure that MISP is up and running and accessible via its web interface.

2. Set Up Wazuh

If you haven’t already, install Wazuh by following the official Wazuh installation guide. Wazuh can be installed on-premises or in the cloud, and it integrates well with various environments.

3. Clone the Integration Repository

Clone the integration repository from GitHub to your Wazuh server:

    git clone https://github.com/shahidakhter786/wazuh-misp.git

This repository contains all the necessary scripts and configuration files needed for the integration.

4. Configure Wazuh

Navigate to the cloned repository and copy the configuration files to your Wazuh installation directory:

    Find all rules and conf. from github repository.

Update the ossec.conf with your specific environment settings, such as the IP addresses of your Wazuh manager and agents.

5. Set Up the MISP Query Script

The custom Python script custom-misp.py is responsible for querying MISP. Ensure Python is installed on your Wazuh server. Update the script with your MISP API key and base URL:

    misp_base_url = “https://your-misp-instance/attributes/restSearch/"
    misp_api_auth_key = “your-misp-api-key”

Place the script in a directory accessible by Wazuh, such as /var/ossec/integrations/.

6. Script Working:

To ensure continuous operation, automate the execution of the MISP query script using mentioning rule ID in ossec.conf or group in that block, which means it will be executed every time whenever that rule or group alert will be triggered.

7. Restart Wazuh

After configuring everything, restart the Wazuh manager to apply the changes:

    systemctl restart wazuh-manager

How the Integration Works

At the heart of this integration is a custom Python script that acts as a bridge between Wazuh and MISP. This script automates the process of querying MISP using IP addresses found in Wazuh alerts. When Wazuh detects a suspicious IP address, the script triggers a query to MISP to check if the IP matches any known IoCs. If a match is found, the script retrieves detailed information from MISP and enriches the original Wazuh alert with this data.

Here’s how it works step by step:

1. Detection: Wazuh detects an event involving a suspicious IP address.
2. Query: The custom Python script queries MISP using the detected IP address.
3. Response: MISP responds with any matching IoCs, including details like threat type, category, and associated metadata.
4. Enrichment: The script then enriches the Wazuh alert with this threat intelligence, providing context and insights that aid in the incident response.

What Information is Shared?

When a matching IoC is found in MISP, the following details are typically included in the enriched Wazuh alert:

- Event ID: The unique identifier of the event in MISP that contains the matched IoC.
- Category: The category of the threat, such as “Network activity” or “Malware.”
- IP Address: The specific IP address that was matched against MISP’s IoC database.
- Type: The type of the IoC, e.g., “ip-dst” (IP destination).
- Timestamp: The time the event or attribute was recorded in MISP.
- Comment: Additional context or comments related to the IoC.
- UUID: A unique identifier for the specific MISP event or attribute.
- Organization ID (Org ID): The ID of the organization that owns the MISP event.
- Creating Organization ID (OrgC ID): The ID of the organization that originally created the IoC.
- Event Information (Info): A brief description of the event or threat related to the IP address.
- Tags: Tags associated with the IoC in MISP, such as names of malware, threat actor identifiers, or campaign identifiers.
