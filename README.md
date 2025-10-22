# Golden-Scan - Professional VirusTotal Scanner

<p align="center">
  <img src="https://i.ibb.co/3mVJs8ZD/Golden-Scan.png" alt="Golden-Scan Logo" width="200">
</p>

A cutting-edge security scanning tool that integrates with the VirusTotal API to analyze files for potential threats with a modern, professional interface.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Report Formats](#report-formats)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

## Features

- **Real-time animated progress tracking** - Visual feedback during scanning operations
- **Interactive visualizations** - Professional dashboard with statistics
- **Modern UI with dark/light themes** - Toggle between themes for comfortable viewing
- **Advanced filtering and search** - Easily find specific scan results
- **Multiple report formats** - Export results in HTML, text, JSON, and CSV formats
- **Live statistics dashboard** - Track malicious, suspicious, and clean files
- **Automatic report generation** - Reports are generated automatically after scanning
- **Batch scanning** - Scan multiple files from an input file
- **File upload to VirusTotal** - Option to upload files not found in VirusTotal database
- **Detailed file analysis** - View comprehensive information about each scanned file

## Requirements

- Python 3.7 or higher
- VirusTotal API key (free from [virustotal.com](https://www.virustotal.com/gui/join-us))
- Required Python packages:
  - tkinter (usually included with Python)
  - requests
  - jinja2
  - pefile (optional, for PE file analysis)

## Installation

1. Clone or download the repository:
   ```bash
   git clone https://github.com/yourusername/golden-scan.git
   cd golden-scan
   ```

2. Install the required packages:
   ```bash
   pip install requests jinja2 pefile
   ```

3. Run the application:
   ```bash
   python golden_scan.py
   ```

## Configuration

### API Key Setup

1. Obtain a free VirusTotal API key from [virustotal.com](https://www.virustotal.com/gui/join-us)
2. When you first run Golden-Scan, you'll be prompted to enter your API key
3. Alternatively, you can set it as an environment variable:
   ```bash
   export VIRUSTOTAL_API_KEY="your_api_key_here"
   ```

### Input File

Golden-Scan reads file paths from an input file (default: `processes.txt`). The application will create a sample input file if one doesn't exist. Each line should contain a file path:

```
C:\Windows\System32\notepad.exe
C:\Windows\System32\calc.exe
C:\Windows\System32\cmd.exe
```

### Settings

You can configure various settings in the Settings tab:

- **API Settings**: Configure your VirusTotal API key
- **Scanner Settings**:
  - Request Interval (seconds): Time to wait between API requests (default: 15)
  - Upload files not found in VT: Automatically upload files not in VirusTotal database
  - Automatically create missing directories
  - Create sample input file if missing

## Usage

### Starting a Scan

1. Launch Golden-Scan
2. Configure your API key if prompted
3. In the Scan tab:
   - Select an input file containing file paths to scan
   - Choose an output directory for reports
   - Click "Start Scan" to begin scanning

### Monitoring Progress

- The Progress section shows the current scan status
- The Dashboard tab displays live statistics
- The Results tab shows detailed scan results as they complete

### Viewing Results

1. Click on any file in the Results tab to see detailed information
2. Double-click a result to view comprehensive file details including:
   - General information (name, path, size, hashes)
   - VirusTotal analysis results
   - PE file analysis (if applicable)

### Generating Reports

After scanning completes, reports are automatically generated in multiple formats:

1. Click "View Reports" to access all generated reports
2. Available formats:
   - HTML Report (interactive with detailed views)
   - Text Report (plain text summary)
   - JSON Report (structured data for further processing)
   - CSV Report (spreadsheet-compatible format)

If threats are detected, additional threat-specific reports are generated.

## Report Formats

### Standard Reports

- **HTML Report**: Interactive report with filtering, sorting, and detailed file views
- **Text Report**: Plain text summary of all scan results
- **JSON Report**: Structured data format for programmatic use
- **CSV Report**: Comma-separated values for spreadsheet applications

### Threats Reports

If malicious or suspicious files are detected, additional reports are generated:

- **Threats HTML Report**: Interactive report focusing only on detected threats
- **Threats Text Report**: Plain text summary of detected threats
- **Threats JSON Report**: Structured data of detected threats

## Troubleshooting

### API Issues

- **Rate Limiting**: VirusTotal has rate limits. Increase the request interval in settings if you encounter rate limit errors.
- **Invalid API Key**: Ensure your API key is valid and has sufficient permissions.

### File Issues

- **File Not Found**: Check that file paths in your input file are correct and accessible.
- **Permission Denied**: Ensure the application has permission to read the files you want to scan.

### Report Issues

- **Report Generation Failed**: Check that the output directory is writable and has sufficient space.
- **Missing Reports**: Reports are only generated after a scan completes. Wait for the scan to finish before viewing reports.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Mohamed A Jaber  
https://www.facebook.com/Mrm0hm3d  
Version: 1.0 (First Edition)
