// src/formatters/utils.ts

import { logToFile } from '../utils/logging.js';

export function formatDateTime(timestamp: number | string | null): string {
  try {
    if (!timestamp) return 'N/A';
    const date = typeof timestamp === 'number' 
      ? new Date(timestamp * 1000)
      : new Date(timestamp);
    return date.toLocaleString();
  } catch (error) {
    logToFile(`Error formatting datetime: ${error}`);
    return 'Invalid Date';
  }
}

export function formatPercentage(num: number, total: number): string {
  try {
    if (total === 0) return '0.0%';
    return `${((num / total) * 100).toFixed(1)}%`;
  } catch (error) {
    logToFile(`Error formatting percentage: ${error}`);
    return '0.0%';
  }
}

export function formatDetectionResults(results: any): string {
  try {
    const malicious = results?.malicious || 0;
    const suspicious = results?.suspicious || 0;
    const harmless = results?.harmless || 0;
    const undetected = results?.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    if (total === 0) {
      return "No detection results available";
    }

    return [
      "Detection Results:",
      `🔴 Malicious: ${malicious} (${formatPercentage(malicious, total)})`,
      `⚠️  Suspicious: ${suspicious} (${formatPercentage(suspicious, total)})`,
      `✅ Clean: ${harmless} (${formatPercentage(harmless, total)})`,
      `⚪ Undetected: ${undetected} (${formatPercentage(undetected, total)})`,
      `📊 Total Scans: ${total}`,
    ].join('\n');
  } catch (error) {
    logToFile(`Error formatting detection results: ${error}`);
    return "Error formatting detection results";
  }
}

/**
 * Render one relationship group for the prompt.
 *
 * Extracted because it was duplicated verbatim in ip.ts, url.ts and file.ts,
 * and the same defect had to be fixed in all three: VirusTotal omits
 * relationship attributes unless asked for them, so a per-type formatter
 * builds a line entirely from 'Unknown' fallbacks and 20 items become 20
 * identical stanzas. The per-type formatters legitimately differ — file.ts
 * handles 14 relationship kinds, ip.ts six — so only the filtering and
 * rendering is shared here, with the caller passing its own formatter in.
 *
 * ip.ts had already drifted from the other two copies before this extraction.
 */
export function renderRelationshipGroup(
  relType: string,
  relData: { data?: any; meta?: { count?: number } },
  renderItem: (relType: string, item: any) => string
): string[] {
  const count =
    relData.meta?.count ?? (Array.isArray(relData.data) ? relData.data.length : 1);

  // Strip Unknown FIELDS, not whole stanzas: an entry carrying a real id
  // followed by "Type: Unknown" would otherwise pass a per-stanza check and
  // print the Unknown lines anyway.
  const stripUnknownFields = (line: string): string => {
    const kept = line.split("\n").filter(l => {
      const i = l.indexOf(":");
      if (i === -1) return l.trim() !== "";          // bare value line
      const v = l.slice(i + 1).trim();
      return v !== "" && v !== "Unknown";
    });
    // Nothing but a bullet left means the item carried no data at all.
    const meaningful = kept.filter(l => l.replace(/^\s*[•\-]\s*/, "").trim() !== "");
    return meaningful.length ? kept.join("\n") : "";
  };

  const rendered: string[] = [];
  const items = Array.isArray(relData.data)
    ? relData.data
    : relData.data
      ? [relData.data]
      : [];
  for (const item of items) {
    const t = stripUnknownFields(renderItem(relType, item));
    if (t) rendered.push(t);
  }

  if (rendered.length) return [`\n${relType} (${count} items):`, ...rendered];
  if (count) return [`\n${relType}: ${count} item(s), no detail returned`];
  return [];
}
