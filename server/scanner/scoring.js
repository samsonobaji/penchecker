'use strict';
/**
 * scoring.js
 * Calculates security score based on ACTUAL findings.
 * Score is always unique per scan based on real vulnerabilities found.
 */

const SEVERITY_DEDUCTIONS = {
  critical: 2.5,
  high: 1.5,
  medium: 0.75,
  low: 0.25,
  info: 0,
};

function calculateScore(findings) {
  let score = 10.0;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const finding of findings) {
    const sev = finding.severity || 'info';
    counts[sev] = (counts[sev] || 0) + 1;
    score -= SEVERITY_DEDUCTIONS[sev] || 0;
  }

  // Apply diminishing returns for multiple findings of same severity
  // (extra critical finding counts less than the first)
  if (counts.critical > 1) score -= (counts.critical - 1) * 0.5;
  if (counts.high > 2) score -= (counts.high - 2) * 0.3;

  // Floor at 0, cap at 10
  score = Math.max(0, Math.min(10, score));

  // Round to 1 decimal
  score = Math.round(score * 10) / 10;

  return {
    score,
    counts,
    total: Object.values(counts).reduce((a, b) => a + b, 0),
    grade: getGrade(score),
    gradeLabel: getGradeLabel(score),
  };
}

function getGrade(score) {
  if (score >= 9) return 'A';
  if (score >= 7.5) return 'B';
  if (score >= 6) return 'C';
  if (score >= 4) return 'D';
  return 'F';
}

function getGradeLabel(score) {
  if (score >= 9) return 'Excellent';
  if (score >= 7.5) return 'Good';
  if (score >= 6) return 'Fair';
  if (score >= 4) return 'Needs Improvement';
  return 'Critical Risk';
}

module.exports = { calculateScore };
