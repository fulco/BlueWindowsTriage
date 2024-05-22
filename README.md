# BlueWindowsTriage
A PowerShell script for rapid initial incident response data collection on a potentially breached Windows system.

This PowerShell script is designed to perform rapid initial data collection on a potentially breached Windows system. It focuses on security, efficiency, and speed to gather crucial information during the early stages of an incident response process.

![](https://github.com/fulco/BlueWindowsTriage/assets/802660/8ecfacea-0a77-48f7-98cc-c8d1ba2aadd7)

## Features

- **System Information Collection**: Captures comprehensive details such as hostname, OS version, uptime, installed software, running processes (including the process owner), and network configuration.
- **User and Group Information**: Gathers data on local users, user groups, and recently created user accounts, including account status and last logon times.
- **Event Logs**: Retrieves and exports the Security, System, and Application logs from the last 24 hours to evtx format, aiding in quick timeline analysis.
- **Active Network Connections**: Documents all current network connections with details like local and remote addresses, port numbers, and the owning process.
- **Registry Analysis**: Examines critical registry keys for autostart configurations, exporting the findings in JSON format for further analysis.
- **File System Analysis**: Performs a recursive search in critical system directories for recently modified files, collecting important metadata and computing SHA-256 hashes for data integrity.
- **Artifact Collection**: Includes PowerShell console history, browser histories (Chrome, Firefox, Edge), cookies, and extensions. This can be crucial for understanding user actions and potential breach points.
- **Scheduled Tasks and Services Analysis**: Provides insights into scheduled tasks and service configurations, which might indicate malicious configurations or tampering.
- **Comprehensive Logging and Error Handling**: Features robust logging to record operational details and errors, facilitating troubleshooting and ensuring a comprehensive audit trail.
- **Output Handling**: Automatically hashes and compresses collected data into a ZIP file for secure transfer, ensuring data integrity and ease of transportation.

## Prerequisites

- Windows operating system
- PowerShell version 3.0 or higher
- Administrative privileges to execute the script and access system resources

## Usage

1. Download the script file `BlueWindowsTriage.ps1` to your local machine.
2. Open a Command console with administrative privileges.
3. Navigate to the directory where the script file is located.
4. Execute the script by running the following command:
   ```
   powershell -ExecutionPolicy Bypass .\BlueWindowsTriage.ps1
   ```
5. The script will create a timestamped output directory in the format `C:\IncidentResponse\yyyyMMdd_HHmmss`.
6. The collected data will be saved in various formats (JSON, CSV, TXT) within the output directory.
7. A log file named `script_log.txt` will be created in the output directory, recording the script's actions and any encountered errors.
8. After the script finishes execution, the output directory will be compressed into a ZIP file with the same name as the directory.
9. Transfer the ZIP file to a secure location for further analysis and investigation.

[See Wiki for more details](https://github.com/fulco/BlueWindowsTriage/wiki/)

## Customization

You can customize the script to fit your specific incident response procedures and environment. Suggestions for customization include adjusting data retention policies, refining data collection scopes based on your organizational needs, and modifying the script to integrate with other IR tools and processes.

## Security Considerations

- Verify you have the necessary permissions and privileges before executing the script.
- Review the script in accordance with your organization's security policies to ensure compliance.
- Handle all collected data according to your organization's data protection policies and relevant legal requirements.
- Keep the script updated with the latest security practices and threat intelligence.

[See Caveat Wiki for more details](https://github.com/fulco/BlueWindowsTriage/wiki/Caveats)

## Disclaimer

This script is provided "as-is" with no warranties, and confers no rights. Use it at your own risk. The authors and contributors are not responsible for any damage or losses that may result from its use.

## License

This script is released under the [MIT License](LICENSE).

## Contributing

Contributions to improve the script are welcome. Please adhere to the standard GitHub workflow for pull requests and maintain the integrity of the original functionality.

## Contact

For any questions or feedback, please contact the script maintainer at [security@fulco.net](mailto:security@fulco.net).
