# Security Monitoring Dashboard

A Python-based security monitoring dashboard that simulates GSOC (Global Security Operations Center) workflows.

## Features

- Real-time log ingestion via CSV upload
- Rule-based incident classification (HIGH / MEDIUM / LOW)
- Incident categorization (Authentication, Physical Access, System Outage)
- Alert triage with escalation logic
- Severity filtering for rapid incident review
- Visualization of event trends and alert distribution

## Tech Stack

- Python
- Streamlit
- Pandas

## How to Run

```bash
pip install -r requirements.txt
streamlit run app.py
