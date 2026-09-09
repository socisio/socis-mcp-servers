# NVD CVE MCP Server Usage Guide

## 📖 Quick Start

### Step 1: Installation and Configuration

1. **Install Dependencies**
```bash
cd nvd-cve-mcp-server
npm install
```

2. **Configure Claude Desktop**

Locate the configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the following configuration:
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

⚠️ **Note**: Using npx is recommended as it doesn't require local installation!

3. **Restart Claude Desktop**

Restart Claude Desktop for the configuration to take effect.

### Step 2: Verify Installation

In Claude, type:
```
What tools do you have available?
```

If you see `get_cve_details` and `search_cves` tools, the installation is successful!

## 🎯 Usage Examples

### Example 1: Query Specific CVE

**User Query:**
```
Please help me query CVE-2025-13583 details
```

**Claude Returns:**
```markdown
# CVE-2025-13583

## 📊 Basic Information

- **CVE ID**: CVE-2025-13583
- **CVSS Score**: 9.8
- **Severity**: CRITICAL
- **Published**: 2025-11-23T10:15:03.000
- **Last Modified**: 2025-11-26T12:39:31.000
- **CWE Type**: CWE-89

## 📝 Description

A vulnerability has been found in code-projects Question Paper Generator 1.0...

## 🔗 References

1. [VulDB](https://vuldb.com/?id.333344)
2. [GitHub](https://github.com/rassec2/dbcve/issues/6)

## 🌐 Official Links

- [NVD Details](https://nvd.nist.gov/vuln/detail/CVE-2025-13583)
- [CVE Record](https://cve.org/CVERecord?id=CVE-2025-13583)
```

### Example 2: Search for SQL Injection Vulnerabilities

**User Query:**
```
Search for recent SQL injection vulnerabilities, show 5 results
```

**Claude Returns:**
```markdown
# CVE Search Results: "SQL injection"

Found 5 related vulnerabilities

| CVE ID | Severity | CVSS | Published | Description |
|--------|----------|------|-----------|-------------|
| CVE-2025-13583 | CRITICAL | 9.8 | 2025-11-23 | A vulnerability has been found in code-projects... |
| CVE-2025-13582 | HIGH | 7.3 | 2025-11-23 | A vulnerability was found in code-projects... |
...
```

### Example 3: Search for Product-Specific Vulnerabilities

**User Query:**
```
Find WordPress-related CVE vulnerabilities
```

**Claude will automatically call the search tool and return results**

### Example 4: Batch Query Multiple CVEs

**User Query:**
```
Please help me query information for these CVEs:
- CVE-2025-13583
- CVE-2025-13582
- CVE-2025-14206
```

**Claude will query each CVE sequentially and organize the results**

## 💡 Advanced Usage

### 1. Combined Queries

```
Search for Apache-related critical vulnerabilities and analyze the top 3 in detail
```

Claude will:
1. Search for Apache-related CVEs
2. Select the top 3 critical vulnerabilities
3. Retrieve detailed information for each
4. Provide comprehensive analysis

### 2. Vulnerability Trend Analysis

```
Search for SQL injection vulnerabilities in 2025 and analyze trends
```

Claude will:
1. Search for relevant CVEs
2. Analyze publication date distribution
3. Summarize vulnerability characteristics and trends

### 3. Security Report Generation

```
Generate a security report on recent WordPress vulnerabilities
```

Claude will:
1. Search for WordPress-related CVEs
2. Retrieve detailed information
3. Analyze severity distribution
4. Generate a formatted security report

## 🔍 Search Tips

### Keyword Selection

**Recommended Search Keywords:**

1. **By Vulnerability Type:**
   - SQL injection
   - XSS (Cross-Site Scripting)
   - RCE (Remote Code Execution)
   - CSRF
   - Buffer Overflow
   - Authentication Bypass

2. **By Product Name:**
   - WordPress
   - Apache
   - MySQL
   - Linux Kernel
   - Microsoft Windows

3. **By Vendor:**
   - Microsoft
   - Oracle
   - Adobe
   - Cisco

4. **By Technology Stack:**
   - PHP
   - Java
   - Python
   - Node.js

### Search Optimization

**Good Search Examples:**
```
Search for "WordPress plugin" vulnerabilities
Search for "Apache Struts" RCE
Search for "Microsoft Exchange" critical vulnerabilities
```

**Avoid:**
```
Search for "vulnerability"  (too broad)
Search for "bug"           (not specific enough)
```

## 📊 Output Format Description

### CVE Details Format

```markdown
# CVE-YYYY-NNNNN

## 📊 Basic Information
- CVE ID: Unique identifier
- CVSS Score: 0-10 scale indicating severity
- Severity: CRITICAL/HIGH/MEDIUM/LOW
- Published: Initial disclosure date
- Last Modified: Most recent update date
- CWE Type: Vulnerability classification

## 📝 Description
Detailed vulnerability explanation

## 🔗 References
Related technical documentation and PoCs

## 🌐 Official Links
NVD and CVE official pages
```

### Search Results Format

Table format including:
- CVE ID (clickable link)
- Severity
- CVSS Score
- Published Date
- Brief Description

## ⚠️ Common Issues

### Q1: Why are there no search results?

**Possible Causes:**
1. Keywords too specific or misspelled
2. Few vulnerabilities of this type
3. API temporarily unavailable

**Solutions:**
- Use more general keywords
- Check spelling
- Retry later

### Q2: Incomplete CVE information?

**Possible Causes:**
1. CVE recently published, information not yet complete
2. Network issues causing partial data loss

**Solutions:**
- Visit NVD official website for latest information
- Wait for CVE information updates

### Q3: Slow query speed?

**Possible Causes:**
1. Slow NVD API response
2. Network latency

**Solutions:**
- System will automatically switch to web scraping
- Be patient or retry later

### Q4: How to get more results?

Default returns 10 results, you can specify:
```
Search for "SQL injection", show 20 results
```

Maximum supported: 20 results.

## 🎓 Learning Resources

### Understanding CVE

- **CVE Official**: https://cve.org/
- **NVD Official**: https://nvd.nist.gov/
- **CVSS Scoring System**: https://www.first.org/cvss/

### Understanding CWE

- **CWE Official**: https://cwe.mitre.org/
- **Common Vulnerability Types**: https://cwe.mitre.org/top25/

### Security Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Security Advisories**: Vendor security bulletin pages

## 📝 Best Practices

### 1. Regular Monitoring

```
Search weekly for vulnerabilities related to your tech stack
Example: "Search for WordPress vulnerabilities from the past week"
```

### 2. Priority Sorting

Focus on:
1. CRITICAL severity vulnerabilities
2. Products/versions you're using
3. Vulnerabilities with public PoCs

### 3. Build Vulnerability Database

Save important CVE information:
```
Please help me organize these CVE details and generate a report
```

### 4. Track Fixes

```
Query CVE-XXXX-XXXXX for remediation solutions
```

## 🔐 Security Reminder

1. **Defensive Use Only**: This tool is for security research and defense
2. **Comply with Laws**: Do not use for illegal attacks
3. **Keep Updated**: Regularly check for system and software updates
4. **Verify Information**: Verify CVE information accuracy before important decisions

## 💬 Getting Help

If you encounter issues:

1. **Check README**: Detailed technical documentation
2. **Verify Configuration**: Ensure paths and configuration are correct
3. **Check Logs**: Review error messages
4. **Submit Issue**: Report problems on GitHub

---

**Enjoy using the tool! 🎉**

Feel free to ask questions in Claude anytime!
