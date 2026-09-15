"""
Audit Document Reviewer
Paste or load a document, or review all documents in a folder at once.

Usage:
  python review_document.py                        <- paste text
  python review_document.py my_document.txt        <- review one file (.txt, .docx, .pdf)
  python review_document.py --folder my_folder     <- review all documents in a folder
"""

import os
import sys

import docx
import pypdf

from llm_provider import LLMClient

SUPPORTED_EXTENSIONS = (".txt", ".docx", ".pdf")


def read_file(file_path: str) -> str:
    """Extract text from .txt, .docx, or .pdf files."""
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext == ".txt":
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

    elif ext == ".docx":
        doc = docx.Document(file_path)
        return "\n".join(paragraph.text for paragraph in doc.paragraphs)

    elif ext == ".pdf":
        reader = pypdf.PdfReader(file_path)
        return "\n".join(page.extract_text() or "" for page in reader.pages)

    else:
        raise ValueError(f"Unsupported file type: {ext}")


def review_document(document_text: str) -> str:
    """Send document to the configured model and print a structured audit review."""

    client = LLMClient()

    system_prompt = """You are an experienced internal auditor.
When given a document, review it and provide a structured assessment with these sections:

1. **Summary** – What the document is about (2-3 sentences)
2. **Key Findings** – What is well-documented and complete
3. **Gaps & Missing Information** – What is unclear, missing, or insufficient
4. **Risks Identified** – Potential risks based on the content
5. **Recommendations** – Concrete steps to improve the document or process

Be specific and practical. Use bullet points within each section."""

    print("\n--- Reviewing document, please wait... ---\n")

    result = []
    for event in client.stream(
        system=system_prompt,
        user=f"Please review the following document:\n\n{document_text}",
        max_tokens=2048,
    ):
        if event.type == "text":
            print(event.text, end="", flush=True)
            result.append(event.text)

    print("\n\n--- Review complete ---\n")
    return "".join(result)


def assess_risk(filename: str, review_text: str) -> dict:
    """Ask the configured model to decide the risk level of a reviewed document."""

    client = LLMClient()

    result = client.complete(
        system="""You are an internal audit risk assessor.
Based on an audit review, assign a risk level and give one short reason.
Respond in exactly this format:
RISK: High | Medium | Low
REASON: one sentence explaining why""",
        user=f"Document: {filename}\n\nReview:\n{review_text}",
        max_tokens=256,
    )

    output = result.text
    risk_level = "Unknown"
    reason = ""

    for line in output.splitlines():
        if line.startswith("RISK:"):
            risk_level = line.replace("RISK:", "").strip()
        elif line.startswith("REASON:"):
            reason = line.replace("REASON:", "").strip()

    return {"file": filename, "risk": risk_level, "reason": reason}


def save_priority_report(assessments: list, reports_folder: str) -> None:
    """Save a priority list sorted by risk level (High first)."""

    order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
    sorted_assessments = sorted(assessments, key=lambda x: order.get(x["risk"], 3))

    report_path = os.path.join(reports_folder, "priority_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("AUDIT PRIORITY REPORT\n")
        f.write("=" * 50 + "\n\n")

        for item in sorted_assessments:
            f.write(f"[{item['risk'].upper()}] {item['file']}\n")
            f.write(f"  → {item['reason']}\n\n")

    print("\n--- Priority Report ---\n")
    for item in sorted_assessments:
        print(f"  [{item['risk'].upper()}] {item['file']}")
        print(f"         {item['reason']}")
    print(f"\nSaved to: {report_path}")


def review_folder(folder_path: str) -> None:
    """Review all documents in a folder, then generate a priority report."""

    if not os.path.isdir(folder_path):
        print(f"Error: Folder '{folder_path}' not found.")
        sys.exit(1)

    txt_files = [f for f in os.listdir(folder_path) if f.lower().endswith(SUPPORTED_EXTENSIONS)]

    if not txt_files:
        print(f"No supported documents (.txt, .docx, .pdf) found in '{folder_path}'.")
        sys.exit(1)

    reports_folder = os.path.join(folder_path, "reports")
    os.makedirs(reports_folder, exist_ok=True)

    print(f"Found {len(txt_files)} document(s) to review.")
    print(f"Reports will be saved to: {reports_folder}\n")

    assessments = []

    for i, filename in enumerate(txt_files, 1):
        file_path = os.path.join(folder_path, filename)
        print(f"[{i}/{len(txt_files)}] Reviewing: {filename}")

        document_text = read_file(file_path)
        review_result = review_document(document_text)

        base_name = os.path.splitext(filename)[0]
        report_filename = base_name + "_review.txt"
        report_path = os.path.join(reports_folder, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"Review of: {filename}\n")
            f.write("=" * 50 + "\n\n")
            f.write(review_result)

        print(f"    Saved report: {report_filename}")
        print(f"    Assessing risk level...")

        assessment = assess_risk(filename, review_result)
        assessments.append(assessment)
        print(f"    Risk: {assessment['risk']}\n")

    print(f"\nAll {len(txt_files)} document(s) reviewed. Generating priority report...")
    save_priority_report(assessments, reports_folder)


def main():
    # Option 1: Review all files in a folder
    if len(sys.argv) > 2 and sys.argv[1] == "--folder":
        review_folder(sys.argv[2])

    # Option 2: Review a single file
    elif len(sys.argv) > 1:
        file_path = sys.argv[1]
        try:
            print(f"Reviewing file: {file_path}")
            document_text = read_file(file_path)
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            sys.exit(1)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        review_document(document_text)

    # Option 3: Paste text directly in the terminal
    else:
        print("Paste your document text below.")
        print("When done, press Enter, then Ctrl+Z (Windows) and Enter to submit.\n")
        lines = []
        try:
            for line in sys.stdin:
                lines.append(line)
        except KeyboardInterrupt:
            pass
        document_text = "".join(lines).strip()

        if not document_text:
            print("No text provided. Exiting.")
            sys.exit(1)
        review_document(document_text)


if __name__ == "__main__":
    main()
