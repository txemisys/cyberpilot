"use client";

export function PrintReportButton() {
  return (
    <button
      className="primary-button report-print-button"
      type="button"
      onClick={() => window.print()}
    >
      Print / Save as PDF
    </button>
  );
}
