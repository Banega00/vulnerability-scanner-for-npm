export const severityLevels = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3
}
export interface AdvisoryPayload {
  ghsa_id: string;
  cve_id: string;
  url: string;
  html_url: string;
  summary: string;
  description: string;
  type: string;
  severity: keyof typeof severityLevels;
  repository_advisory_url: string;
  source_code_location: string;
  identifiers: any[]; // Define a more specific type if available
  references: string[];
  published_at: string;
  updated_at: string;
  github_reviewed_at: string;
  nvd_published_at: string;
  withdrawn_at: string;
  vulnerabilities: VulnerabilityPayload[]; // Define a more specific type if available
  cvss: {
    vector_string: string;
    score: number;
  };
  cwes: any[]; // Define a more specific type if available
  credits: any[]; // Define a more specific type if available
}

interface VulnerabilityPayload {
  package: {
    ecosystem: string;
    name: string;
  };
  vulnerable_version_range: string;
  first_patched_version: string;
  vulnerable_functions: string[];
}
