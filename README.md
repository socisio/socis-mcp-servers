# NVD CVE MCP Server

[![npm version](https://badge.fury.io/js/nvd-cve-mcp-server.svg)](https://www.npmjs.com/package/nvd-cve-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server for retrieving and displaying CVE vulnerability information from the National Vulnerability Database (NVD). Features dual data sources with NVD API and web scraping fallback.

## ✨ Features

- 🔍 **CVE Details Lookup**: Retrieve complete vulnerability information by CVE ID
- 🔎 **Keyword Search**: Search for CVE vulnerabilities by keywords
- 📊 **Formatted Output**: Display vulnerability information in elegant Markdown format
- 🔄 **Dual Data Sources**: API-first approach with web scraping as fallback
- 🌐 **Multi-language Support**: Full support for both English and Chinese

## 📦 Installation

### Prerequisites

- Node.js >= 18.0.0
- npm or yarn

### Quick Start with npx (Recommended)

No installation required! Use directly with npx:

```json
{
  "mcpServers": {
    "nvd-cve": {
      "command": "npx",
      "args": ["-y", "nvd-cve-mcp-server"]
    }
  }
}
```

### Global Installation

```bash
npm install -g nvd-cve-mcp-server
```

### Local Installation

```bash
npm install nvd-cve-mcp-server
```

## 🚀 Usage

### 1. Configure as MCP Server

Configure in Claude Desktop or other MCP-compatible applications:

**macOS/Linux** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "nvd-cve": {
      "command": "npx",
      "args": ["-y", "nvd-cve-mcp-server"]
    }
  }
}
```

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "nvd-cve": {
      "command": "npx",
      "args": ["-y", "nvd-cve-mcp-server"]
    }
  }
}
```

### 2. Direct Execution

```bash
npm start
```

## 🛠️ Available Tools

### 1. get_cve_details

Retrieve detailed information for a specific CVE.

**Parameters:**
- `cve_id` (required): CVE ID in format CVE-YYYY-NNNNN

**Example:**
```
Get details for CVE-2025-13583
```

**Output Format:**
```markdown
# CVE-2025-13583

## 📊 Basic Information

- **CVE ID**: CVE-2025-13583
- **CVSS Score**: 9.8
- **Severity**: CRITICAL
- **Published**: 2025-11-23
- **Last Modified**: 2025-11-26
- **CWE Type**: CWE-89

## 📝 Description

[Detailed vulnerability description]

## 🔗 References

1. [VulDB](https://vuldb.com/?id.333344)
2. [GitHub Issue](https://github.com/rassec2/dbcve/issues/6)

## 🌐 Official Links

- [NVD Details](https://nvd.nist.gov/vuln/detail/CVE-2025-13583)
- [CVE Record](https://cve.org/CVERecord?id=CVE-2025-13583)
```

### 2. search_cves

Search for CVE vulnerabilities by keyword.

**Parameters:**
- `keyword` (required): Search keyword
- `limit` (optional): Number of results to return (default: 10, max: 20)

**Example:**
```
Search for CVEs related to "SQL injection"
Search for "WordPress" vulnerabilities, limit to 5 results
```

**Output Format:**
```markdown
# CVE Search Results: "SQL injection"

Found 10 related vulnerabilities

| CVE ID | Severity | CVSS | Published | Description |
|--------|----------|------|-----------|-------------|
| CVE-2025-13583 | CRITICAL | 9.8 | 2025-11-23 | A vulnerability has been found in code-projects... |
| CVE-2025-13582 | HIGH | 7.3 | 2025-11-23 | A vulnerability was found in code-projects... |
```

## 📋 Usage Examples

### Using with Claude

1. **Query Specific CVE:**
   ```
   Please help me query CVE-2025-13583 details
   ```

2. **Search Vulnerabilities:**
   ```
   Search for recent SQL injection vulnerabilities
   ```

3. **Search by Product:**
   ```
   Find WordPress-related CVE vulnerabilities
   ```

## 🔧 Technical Architecture

### Data Sources

1. **NVD API** (Primary)
   - Official REST API: `https://services.nvd.nist.gov/rest/json/cves/2.0`
   - Provides structured JSON data
   - Includes complete CVSS scores, CWE classifications, etc.

2. **NVD Web** (Fallback)
   - Web scraping when API is unavailable
   - Uses Cheerio for HTML parsing
   - Extracts key vulnerability information

### Core Dependencies

- `@modelcontextprotocol/sdk`: MCP protocol implementation
- `axios`: HTTP client
- `cheerio`: HTML parser

## 📊 Data Format

### CVE Details Object

```javascript
{
  id: "CVE-2025-13583",
  description: "Vulnerability description...",
  cvssScore: 9.8,
  severity: "CRITICAL",
  published: "2025-11-23T10:15:03.000",
  lastModified: "2025-11-26T12:39:31.000",
  references: [
    {
      url: "https://example.com",
      source: "VulDB"
    }
  ],
  cweId: "CWE-89",
  source: "api" // or "web"
}
```

## ⚠️ Important Notes

1. **API Rate Limits**: NVD API has rate limits, please use responsibly
2. **Network Requirements**: Requires access to nvd.nist.gov
3. **Data Freshness**: CVE information is updated regularly, check for latest data
4. **Format Validation**: CVE ID must follow CVE-YYYY-NNNNN format

## 🐛 Troubleshooting

### Common Issues

1. **API Timeout**
   - Check network connection
   - System will automatically switch to web scraping mode

2. **CVE Not Found**
   - Verify CVE ID format is correct
   - Check if CVE has been published to NVD

3. **No Search Results**
   - Try using more general keywords
   - Check spelling

## 📝 Development

### Project Structure

```
nvd-cve-mcp-server/
├── src/
│   └── index.js          # Main server code
├── package.json          # Project configuration
└── README.md            # Documentation
```

### Local Development

```bash
# Development mode (auto-restart)
npm run dev

# Production mode
npm start
```

## 🤝 Contributing

Issues and Pull Requests are welcome!

## 📄 License

MIT License

## 👥 Author

0x4hm3d

## 🔗 Related Links

- [NPM Package](https://www.npmjs.com/package/nvd-cve-mcp-server)
- [GitHub Repository](https://github.com/0x4hm3d/nvd-cve-mcp-server)
- [NVD Official Website](https://nvd.nist.gov/)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [MCP Protocol](https://modelcontextprotocol.io/)
- [CVE Official Website](https://cve.org/)

---

**Note**: This tool is for security research and educational purposes only. Please comply with relevant laws, regulations, and ethical standards.

## Configuration

### `NVD_API_KEY` (optional, strongly recommended)

NVD rate-limits unauthenticated callers to **5 requests per rolling 30 seconds**.
With a free API key that rises to **50**.

Without a key you will hit the limit during ordinary use, and the failure is
quiet: the server falls back to scraping the NVD web page, which returns no CWE
classification and no reference links. Since v1.1.0 that degradation is
announced at the top of the report rather than inferred from a footer, but the
data is still incomplete.

Request a key (free, instant): https://nvd.nist.gov/developers/request-an-api-key

```json
{
  "mcpServers": {
    "nvd-cve": {
      "command": "npx",
      "args": ["-y", "nvd-cve-mcp-server"],
      "env": { "NVD_API_KEY": "your-key-here" }
    }
  }
}
```

The key is optional — the server runs without it.

## Security notes

- **No credentials are required** for basic operation and none are stored.
- **CVE IDs are validated against `/^CVE-\d{4}-\d{4,}$/` before use.** This runs
  before the ID reaches a URL, which is what prevents path traversal and SSRF in
  the web-scraping fallback. Do not relax it.
- **Requests go only to `services.nvd.nist.gov` and `nvd.nist.gov`.** There is no
  user-controlled URL anywhere in the code.
- **Dependencies use caret ranges with no upper bound**, so `npm install` picks
  up security patches. This is deliberate: an upper bound added during the March
  2026 axios supply-chain incident left several other MCP servers pinned below
  the fix for CVE-2026-40175 (CVSS 9.9).
