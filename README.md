# BlueWindowsTriage
A PowerShell script for rapid initial incident response data collection on a potentially breached Windows system.

This PowerShell script is designed to perform rapid initial data collection on a potentially breached Windows system. It focuses on security, efficiency, and speed to gather crucial information during the early stages of an incident response process.

## Features

- Collects system information, including hostname, OS version, uptime, installed software, running processes, and network configuration.
- Gathers user and group information, such as local users, user groups, and recently created user accounts.
- Retrieves relevant event logs (Security, System, Application) from the last 24 hours and exports them to CSV files.
- Captures active network connections and their details.
- Analyzes critical registry keys related to autostart locations and exports their values to JSON files.
- Performs a recursive search for recently modified files in critical system directories and collects file metadata and hashes.
- Collects additional artifacts such as PowerShell console history and browser history.
- Compresses the output directory into a ZIP file for easy transfer and removes the original directory.

## Prerequisites

- Windows operating system
- PowerShell version 3.0 or higher
- Administrative privileges to execute the script and access system resources

## Usage

1. Download the script file `rapid_ir_data_collection.ps1` to your local machine.

2. Open a PowerShell console with administrative privileges.

3. Navigate to the directory where the script file is located.

4. Execute the script by running the following command:
   ```
   .\rapid_ir_data_collection.ps1
   ```

5. The script will create a timestamped output directory in the format `C:\IncidentResponse\yyyyMMdd_HHmmss`.

6. The collected data will be saved in various formats (JSON, CSV) within the output directory.

7. After the script finishes execution, the output directory will be compressed into a ZIP file with the same name as the directory.

8. Transfer the ZIP file to a secure location for further analysis and investigation.

## Customization

You can customize the script to fit your specific incident response procedures and environment. Here are a few possible modifications:

- Adjust the output directory path and naming convention in the `$outputDir` variable.
- Modify the event log collection to include additional logs or change the time range.
- Add or remove specific registry keys to analyze based on your requirements.
- Customize the file system analysis to include additional directories or modify the search criteria.
- Extend the artifact collection to include other relevant files or locations.

## Security Considerations

- Ensure that you have the necessary permissions and privileges to execute the script and access system resources.
- Review and validate the script before running it on a production system to ensure it aligns with your organization's security policies.
- Handle the collected data securely and in accordance with your organization's policies and legal requirements.
- Regularly update the script to address new security threats, system changes, and best practices in incident response.

## Disclaimer

This script is provided as-is without any warranty. Use it at your own risk. The authors and contributors shall not be liable for any damages or consequences arising from the use of this script.

## License

This script is released under the [MIT License](LICENSE).

## Contributing

Contributions to improve the script are welcome. Please follow the standard GitHub workflow for pull requests.

## Contact

For any questions or feedback, please contact the script maintainer at [security@fulco.net].
