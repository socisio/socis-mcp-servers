#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import * as cheerio from 'cheerio';

// NVD API configuration
const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// NVD rate limits unauthenticated callers to 5 requests per rolling 30 seconds.
// With a free key that becomes 50. An analyst working through a handful of CVEs
// will hit the anonymous limit routinely, and the failure mode is not an error
// the user sees — it is a silent fall back to web scraping, which returns no
// CWE and no references (see getCVEFromWeb). Degraded data that looks like good
// data is the worst outcome for a security tool, so the key is worth setting.
//
// Free, no account approval delay: https://nvd.nist.gov/developers/request-an-api-key
const NVD_API_KEY = process.env.NVD_API_KEY || '';

/** Headers for NVD API calls. The key header is only sent when one is set. */
function nvdHeaders() {
    return NVD_API_KEY ? { apiKey: NVD_API_KEY } : {};
}
const NVD_WEB_BASE = 'https://nvd.nist.gov/vuln/detail';

// Create MCP server
const server = new Server(
    {
        name: 'socis-mcp-nvd',
        version: '1.3.0',
    },
    {
        capabilities: {
            tools: {},
        },
    }
);

/**
 * Get CVE details from NVD API
 */
async function getCVEDetails(cveId) {
    try {
        const response = await axios.get(`${NVD_API_BASE}`, {
            params: {
                cveId: cveId
            },
            headers: nvdHeaders(),
            timeout: 15000
        });

        if (response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
            const vuln = response.data.vulnerabilities[0].cve;
            return formatCVEData(vuln);
        }
        return null;
    } catch (error) {
        // 429/403 from NVD almost always means the anonymous rate limit, not a
        // missing CVE. Record which it was so the caller can say so rather than
        // presenting scraped data as if it were the API's.
        const status = error.response?.status;
        const rateLimited = status === 429 || status === 403;
        console.error(
            rateLimited
                ? `NVD rate limit hit (HTTP ${status}) — falling back to web scraping. `
                  + `Set NVD_API_KEY to raise the limit from 5 to 50 requests/30s.`
                : `NVD API fetch failed (${error.message}) — falling back to web scraping.`
        );
        const scraped = await getCVEFromWeb(cveId);
        if (scraped) {
            scraped.degradedReason = rateLimited
                ? `NVD API rate limit (HTTP ${status})`
                : `NVD API error: ${error.message}`;
        }
        return scraped;
    }
}

/**
 * Scrape CVE info from NVD web (fallback)
 */
async function getCVEFromWeb(cveId) {
    try {
        const response = await axios.get(`${NVD_WEB_BASE}/${cveId}`, {
            timeout: 15000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        const $ = cheerio.load(response.data);

        const description = $('[data-testid="vuln-description"]').text().trim() ||
            $('.vuln-description').text().trim() ||
            'Description not available';

        const cvssScore = $('[data-testid="vuln-cvss3-panel-score"]').text().trim() ||
            $('.severityDetail').first().text().trim() ||
            'N/A';

        const published = $('[data-testid="vuln-published-on"]').text().trim() ||
            'N/A';

        const modified = $('[data-testid="vuln-last-modified-on"]').text().trim() ||
            'N/A';

        return {
            id: cveId,
            description: description,
            cvssScore: cvssScore,
            severity: extractSeverity(cvssScore),
            published: published,
            lastModified: modified,
            references: [],
            cweId: 'N/A',
            source: 'web'
        };
    } catch (error) {
        throw new Error(`Unable to fetch CVE information: ${error.message}`);
    }
}

/**
 * Search CVEs by keyword, most recently modified first.
 *
 * WHY THE DATE WINDOW EXISTS. NVD returns keyword results in its own internal
 * order, which is roughly CVE-ID ascending — so an unfiltered search for a
 * long-lived product returns its OLDEST entries. Searching "FortiOS" returned
 * CVE-2005-1837 through CVE-2014-2216 and nothing from this decade, which
 * makes the tool useless for the single most common question an analyst asks:
 * "what has come out recently for X?"
 *
 * Sorting client-side does not fix it. With resultsPerPage=10 the page itself
 * contains only the oldest ten, so there is nothing recent in it to sort. The
 * filter has to go to the API.
 *
 * PUBLISHED, NOT LAST-MODIFIED, BY DEFAULT.
 *
 * The first version of this filtered on lastModStartDate, reasoning that a CVE
 * re-scored last week matters to a defender even if published in 2023. That is
 * true in principle and wrong in practice: NVD has been bulk re-enriching its
 * backlog, so a last-modified window returns a flood of 2005-2016 CVEs whose
 * metadata was touched by housekeeping. The genuine signal drowns.
 *
 * pubStartDate answers what an analyst actually means by "recent" — newly
 * published vulnerabilities. Pass by_modified: true to get the re-scored view
 * deliberately, knowing it includes the backlog noise.
 *
 * 120 DAYS IS NVD'S HARD LIMIT for a single lastModStartDate/EndDate span.
 * A longer range returns an error rather than truncating, so it is clamped.
 */
async function searchCVEs(keyword, resultsPerPage = 20, recentDays = 120, byModified = false) {
    try {
        const params = {
            keywordSearch: keyword,
            // NVD's own maximum is 2000; the tool schema caps lower still.
            resultsPerPage: Math.min(resultsPerPage, 2000)
        };

        if (recentDays && recentDays > 0) {
            const days = Math.min(recentDays, 120);
            const end = new Date();
            const start = new Date(end.getTime() - days * 86400000);
            // NVD wants ISO-8601; it accepts the trailing Z form.
            if (byModified) {
                params.lastModStartDate = start.toISOString();
                params.lastModEndDate = end.toISOString();
            } else {
                params.pubStartDate = start.toISOString();
                params.pubEndDate = end.toISOString();
            }
        }

        const response = await axios.get(`${NVD_API_BASE}`, {
            params,
            headers: nvdHeaders(),
            timeout: 20000
        });

        const vulns = response.data.vulnerabilities || [];

        // Newest first. NVD does not sort for us, and a reader scanning a
        // vulnerability list top-down expects the most recent at the top.
        const formatted = vulns.map(v => formatCVEData(v.cve));
        formatted.sort((a, b) => {
            const da = Date.parse(a.published) || 0;
            const db = Date.parse(b.published) || 0;
            return db - da;
        });
        return formatted;
    } catch (error) {
        // A 404 here usually means the date window was malformed or too wide,
        // not that the keyword matched nothing — say so rather than letting the
        // caller conclude the product has no CVEs.
        const status = error.response?.status;
        if (status === 404) {
            throw new Error(
                `Search failed (HTTP 404). If you passed recent_days, NVD limits a `
                + `single last-modified window to 120 days. Original: ${error.message}`
            );
        }
        if (status === 429 || status === 403) {
            throw new Error(
                `Search rate-limited (HTTP ${status}). NVD allows 5 requests per 30s `
                + `without a key, 50 with one. Set NVD_API_KEY. Original: ${error.message}`
            );
        }
        throw new Error(`Search failed: ${error.message}`);
    }
}

/**
 * Format CVE data
 */
function formatCVEData(cve) {
    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';

    let cvssScore = 'N/A';
    let severity = 'N/A';

    if (cve.metrics?.cvssMetricV31?.[0]) {
        const cvss = cve.metrics.cvssMetricV31[0];
        cvssScore = cvss.cvssData.baseScore;
        severity = cvss.cvssData.baseSeverity;
    } else if (cve.metrics?.cvssMetricV30?.[0]) {
        const cvss = cve.metrics.cvssMetricV30[0];
        cvssScore = cvss.cvssData.baseScore;
        severity = cvss.cvssData.baseSeverity;
    } else if (cve.metrics?.cvssMetricV2?.[0]) {
        const cvss = cve.metrics.cvssMetricV2[0];
        cvssScore = cvss.cvssData.baseScore;
        severity = cvss.baseSeverity;
    }

    // NVD tags references — Vendor Advisory, Patch, Exploit, Mitigation — and
    // the old code discarded the tags then kept whichever five came first.
    // For Log4Shell that surfaced five Packet Storm mirrors while Apache's own
    // advisory and the patch link sat further down the list. Rank by what the
    // reference IS, then cap; 5 was too few to reach a vendor advisory and the
    // untruncated list runs to 60+ mailing-list mirrors.
    const TAG_RANK = {
        'Vendor Advisory': 0,
        'Patch': 1,
        'Mitigation': 2,
        'Exploit': 3,
        'Third Party Advisory': 4,
        'US Government Resource': 5,
    };
    const rankOf = (ref) => Math.min(
        ...(ref.tags?.length ? ref.tags.map(t => TAG_RANK[t] ?? 90) : [99])
    );
    // NVD lists the same URL once per CNA that submitted it, so the raw list
    // carries duplicates. Ranking made them adjacent and obvious: Apache's
    // advisory and Microsoft's MSRC post each appeared twice, spending 8 of 15
    // slots on 4 unique links. Merge tags across duplicates rather than
    // dropping one arbitrarily — the copies often carry different tags.
    const byUrl = new Map();
    for (const ref of cve.references || []) {
        const seen = byUrl.get(ref.url);
        if (seen) {
            seen.tags = [...new Set([...(seen.tags || []), ...(ref.tags || [])])];
        } else {
            byUrl.set(ref.url, { ...ref, tags: [...(ref.tags || [])] });
        }
    }
    const references = [...byUrl.values()]
        .map((ref, i) => ({ ref, i, rank: rankOf(ref) }))
        .sort((a, b) => a.rank - b.rank || a.i - b.i)   // stable within a rank
        .slice(0, 15)
        .map(({ ref }) => ({
            url: ref.url,
            source: ref.source || 'N/A',
            tags: ref.tags || []
        }));

    const cweId = cve.weaknesses?.[0]?.description?.[0]?.value || 'N/A';

    return {
        id: cve.id,
        description: description,
        cvssScore: cvssScore,
        severity: severity,
        published: cve.published || 'N/A',
        lastModified: cve.lastModified || 'N/A',
        references: references,
        cweId: cweId,
        source: 'api'
    };
}

/**
 * Extract severity from CVSS score
 */
function extractSeverity(cvssText) {
    if (cvssText.includes('CRITICAL')) return 'CRITICAL';
    if (cvssText.includes('HIGH')) return 'HIGH';
    if (cvssText.includes('MEDIUM')) return 'MEDIUM';
    if (cvssText.includes('LOW')) return 'LOW';
    return 'N/A';
}

/**
 * Format CVE info to Markdown
 */
function formatCVEMarkdown(cve) {
    let markdown = `# ${cve.id}\n\n`;

    // A degradation notice belongs at the top. The footer already named the
    // source, but a reader scanning a CVE report will not infer from "NVD Web"
    // that CWE and references are absent because of a rate limit rather than
    // because NVD has none. State the consequence, not just the source.
    if (cve.source !== 'api') {
        markdown += `> **INCOMPLETE DATA** — retrieved by web scraping`
            + `${cve.degradedReason ? ` (${cve.degradedReason})` : ''}, not the NVD API.\n`
            + `> CWE classification and reference links are **not available** in this mode.\n`
            + `> Set \`NVD_API_KEY\` for complete records, or check the NVD page linked below.\n\n`;
    }
        markdown += `## 📊 Basic Information\n\n`;
        markdown += `- **CVE ID**: ${cve.id}\n`;
        markdown += `- **CVSS Score**: ${cve.cvssScore}\n`;
        markdown += `- **Severity**: ${cve.severity}\n`;
        markdown += `- **Published**: ${cve.published}\n`;
        markdown += `- **Last Modified**: ${cve.lastModified}\n`;
        markdown += `- **CWE Type**: ${cve.cweId}\n\n`;

    markdown += `## 📝 Vulnerability Description\n\n`;
    markdown += `${cve.description}\n\n`;

    if (cve.references && cve.references.length > 0) {
        markdown += `## 🔗Reference Links\n\n`;
        // Label each link with what it IS, not who reported it. Using
        // ref.source rendered five consecutive "security@apache.org" links for
        // Log4Shell — the same text five times, telling the reader nothing
        // about which one is the vendor advisory and which is a mirror.
        cve.references.forEach((ref, index) => {
            const label = ref.tags?.length ? ref.tags.join(', ') : ref.source;
            markdown += `${index + 1}. **${label}** — <${ref.url}>\n`;
        });
        markdown += `\n`;
    }

        markdown += `## 🌐 Official Links\n\n`;
        markdown += `- [NVD Detail Page](https://nvd.nist.gov/vuln/detail/${cve.id})\n`;
        markdown += `- [CVE Official Record](https://cve.org/CVERecord?id=${cve.id})\n\n`;

        markdown += `---\n`;
        markdown += `*Data source: ${cve.source === 'api' ? 'NVD API' : 'NVD Web'}*\n`;

    return markdown;
}

/**
 * Format search results to Markdown table
 */
function formatSearchResults(cves, keyword, recentDays, byModified) {
    let markdown = `# CVE search results: "${keyword}"\n\n`;
        markdown += `Found ${cves.length} related vulnerabilities`;
        // State the window. Without it, a reader cannot tell whether a short
        // list means "few vulnerabilities" or "few CHANGED recently".
        markdown += recentDays && recentDays > 0
            ? ` ${byModified ? 'modified' : 'published'} in the last ${recentDays} days, newest first.\n\n`
            : ` across all time (NVD ordering — oldest first).\n\n`;
        // Say so when the backlog-noise mode is in use, otherwise a list of
        // 2005 CVEs under a "recent" heading reads as a broken tool.
        if (byModified && recentDays > 0) {
            markdown += `> Filtered by LAST-MODIFIED date. NVD is re-enriching its backlog, so\n`
                + `> old CVEs appear here when their metadata changed. Omit \`by_modified\`\n`
                + `> to see only newly PUBLISHED vulnerabilities.\n\n`;
        }
        markdown += `| CVE ID | Severity | CVSS | Published | Description |\n`;
        markdown += `|--------|---------|------|---------|------|\n`;

    cves.forEach(cve => {
        const shortDesc = cve.description.length > 100
            ? cve.description.substring(0, 100) + '...'
            : cve.description;
            markdown += `| [${cve.id}](https://nvd.nist.gov/vuln/detail/${cve.id}) | ${cve.severity} | ${cve.cvssScore} | ${cve.published.split('T')[0]} | ${shortDesc.replace(/\|/g, '\\|')} |\n`;
    });

        markdown += `\n---\n`;
        markdown += `*Data source: NVD API*\n`;

    return markdown;
}

// Register tool list
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: 'get_cve_details',
                description: 'Get detailed vulnerability information by CVE ID, including description, CVSS score, severity, reference links, etc.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        cve_id: {
                            type: 'string',
                            description: 'CVE ID (e.g., CVE-2025-13583)',
                            pattern: '^CVE-\\d{4}-\\d{4,}$'
                        }
                    },
                    required: ['cve_id']
                }
            },
            {
                name: 'search_cves',
                description:
                    'Search CVE vulnerabilities by keyword (product, vendor, or description text). '
                    + 'Returns CVEs PUBLISHED within the last `recent_days` (default 120, '
                    + "NVD's maximum single window), sorted newest first — this answers "
                    + '"what has come out recently for X?". Set recent_days to 0 for an all-time '
                    + 'search, but note NVD then returns its own ordering, which surfaces the '
                    + 'OLDEST matches first; for a long-lived product that means 20-year-old CVEs.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        keyword: {
                            type: 'string',
                            description: 'Search keyword (e.g., FortiOS, SQL injection, WordPress, Apache)'
                        },
                        limit: {
                            type: 'number',
                            description: 'Limit on number of results returned (default: 20, max: 50)',
                            default: 20,
                            minimum: 1,
                            maximum: 50
                        },
                        recent_days: {
                            type: 'number',
                            description:
                                'Look back this many days. Default 120 '
                                + "(NVD's maximum span). Use 0 to disable the filter and search "
                                + 'all time — rarely what you want, see the tool description.',
                            default: 120,
                            minimum: 0,
                            maximum: 120
                        },
                        by_modified: {
                            type: 'boolean',
                            description:
                                'Filter by LAST-MODIFIED date instead of published date. '
                                + 'Default false. Useful for catching CVEs whose CVSS was '
                                + 'recently re-scored — but NVD is bulk re-enriching its '
                                + 'backlog, so this also returns many 2005-2016 CVEs whose '
                                + 'metadata changed for housekeeping reasons rather than '
                                + 'because anything about the vulnerability changed.',
                            default: false
                        }
                    },
                    required: ['keyword']
                }
            }
        ]
    };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
        if (name === 'get_cve_details') {
            // Check the type before calling a string method on it. A missing or
            // non-string cve_id previously threw a raw TypeError ("Cannot read
            // properties of undefined"), which the catch below dutifully
            // returned to the model as the error text — unhelpful to a caller
            // trying to correct itself.
            if (typeof args?.cve_id !== 'string' || !args.cve_id.trim()) {
                throw new Error('cve_id is required and must be a string, e.g. "CVE-2024-3400".');
            }

            const cveId = args.cve_id.trim().toUpperCase();

            // Validate the format BEFORE the ID reaches a URL. getCVEFromWeb
            // interpolates it into a path, so this regex is the control that
            // prevents path traversal and SSRF — not cosmetic input tidying.
            if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
                throw new Error('Invalid CVE ID format. Expected CVE-YYYY-NNNNN, e.g. CVE-2024-3400.');
            }

            const cveData = await getCVEDetails(cveId);

            if (!cveData) {
                throw new Error(`CVE not found: ${cveId}`);
            }

            const markdown = formatCVEMarkdown(cveData);

            return {
                content: [
                    {
                        type: 'text',
                        text: markdown
                    }
                ]
            };
        }

        if (name === 'search_cves') {
            if (typeof args?.keyword !== 'string' || !args.keyword.trim()) {
                throw new Error('keyword is required and must be a non-empty string.');
            }
            // NVD rejects very long keyword queries outright; failing here gives
            // a better message than a 404 from upstream.
            const keyword = args.keyword.trim().slice(0, 200);
            const limit = Math.min(Math.max(parseInt(args.limit, 10) || 20, 1), 50);

            // recent_days needs an explicit undefined check: `|| 120` would
            // turn a deliberate 0 (all-time search) back into the default.
            const rawDays = args.recent_days;
            const recentDays =
                rawDays === undefined || rawDays === null || rawDays === ''
                    ? 120
                    : Math.min(Math.max(parseInt(rawDays, 10) || 0, 0), 120);

            const byModified = args.by_modified === true;

            const results = await searchCVEs(keyword, limit, recentDays, byModified);

            if (results.length === 0) {
                return {
                    content: [
                        {
                            type: 'text',
                            text: recentDays > 0
                                ? `No CVEs matching "${keyword}" were modified in the last ${recentDays} days.\n\n`
                                  + `This does NOT mean the product has no vulnerabilities — only that none `
                                  + `changed recently. To search all time, call again with recent_days: 0 `
                                  + `(results will be oldest-first, which is NVD's ordering).\n\n`
                                  + `Other things to try:\n- A broader keyword (vendor instead of product)\n`
                                  + `- Check spelling`
                                : `No CVE vulnerabilities found related to "${keyword}" at any date.\n\n`
                                  + `Suggestions:\n- Try different keywords\n- Use more generic terms\n- Check spelling` 
                        }
                    ]
                };
            }

            const markdown = formatSearchResults(results, keyword, recentDays, byModified);

            return {
                content: [
                    {
                        type: 'text',
                        text: markdown
                    }
                ]
            };
        }

        throw new Error(`Unknown tool: ${name}`);
    } catch (error) {
            return {
                content: [
                    {
                        type: 'text',
                        text: `❌ Error: ${error.message}`
                    }
                ],
                isError: true
            };
    }
});

// Start server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('NVD CVE MCP Server started');
}

main().catch((error) => {
    console.error('Server startup failed:', error);
    process.exit(1);
});
