// Render promptfoo-results.json as a Markdown table for the GitHub job summary.
const fs = require("fs");

let md = `## Digest eval (${process.env.PROVIDER || "?"})\n\n`;
try {
  const d = JSON.parse(fs.readFileSync("promptfoo-results.json", "utf8"));
  const rows = d.results?.results || [];
  const passed = rows.filter((r) => r.success).length;
  md += `**${passed}/${rows.length} scenarios passed**\n\n`;
  md += "| Scenario | Result | Scores |\n|---|---|---|\n";
  for (const r of rows) {
    const scores = (r.gradingResult?.componentResults || [])
      .map((c) => `${c.assertion?.metric || c.assertion?.type}: ${c.score}${c.pass ? "" : " ❌"}`)
      .join("<br>");
    md += `| ${r.vars?.scenario} | ${r.success ? "✅" : "❌"} | ${scores} |\n`;
  }
} catch (e) {
  md += `_No results to summarize (${e.message})._\n`;
}
process.stdout.write(md);
