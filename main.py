import pandas as pd
import json
import os
import sys
from pydantic import BaseModel
from typing import List, Literal, Optional

class AuditStep(BaseModel):
    step_no: int
    phase: Literal["FINDING", "REMEDIATION", "VERIFICATION"]
    system_id: str
    resource_id: str
    operation: Literal[
        "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", 
        "REPORT_RESTORE_RISK", "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", 
        "REDACT_RECORD", "ANONYMIZE_RECORD", "VERIFY_RECORD_ABSENT", 
        "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED", 
        "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"
    ]
    state: Literal["PRESENT", "ACTIVE", "DISABLED", "BLOCKED", "ABSENT", "REDACTED", "ANONYMIZED"]
    evidence_id: Optional[str] = ""

def load_data():
    base_path = "dataset"
    print(f"Checking for data in: {os.path.abspath(base_path)}")
    
    if not os.path.exists(base_path):
        print(f"CRITICAL ERROR: The '{base_path}' folder was not found.")
        sys.exit(1)

    # List of files we expect based on the problem statement
    required_files = [
        "deletion_requests.csv", 
        "user_identities.csv", 
        "system_activity.csv", 
        "deletion_rules.csv", 
        "user_audit_log.csv"
    ]
    
    data = {}
    
    for file in required_files:
        file_path = os.path.join(base_path, file)
        key_name = file.split('_')[0] if file != "deletion_requests.csv" else "requests"
        
        if not os.path.exists(file_path):
            print(f"WARNING: Missing file {file_path}. Creating an empty placeholder.")
            # Create an empty dataframe so the script doesn't crash
            data[key_name] = pd.DataFrame()
        else:
            data[key_name] = pd.read_csv(file_path)
            
    # Ensure at least deletion_requests.csv exists to generate output
    if data["requests"].empty:
        print("CRITICAL ERROR: deletion_requests.csv is missing or empty. Cannot generate output.csv.")
        sys.exit(1)
        
    return data

def analyze_case(case_row, data):
    request_text = str(case_row.get("request_text", "")).lower()
    if "delete" not in request_text and "remove" not in request_text:
        return "NOT_APPLICABLE", []
    return "INCOMPLETE", [] 

def format_steps(steps: List[AuditStep]) -> List[dict]:
    if not steps: return []
    phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
    operation_order = {
        "REPORT_REMAINING_RECORD": 1, "REPORT_EXPOSED_PII": 2, "REPORT_ACTIVE_DATA_FLOW": 3, "REPORT_RESTORE_RISK": 4,
        "DISABLE_DATA_FLOW": 5, "BLOCK_RESTORE": 6, "DELETE_RECORD": 7, "REDACT_RECORD": 8, "ANONYMIZE_RECORD": 9,
        "VERIFY_RECORD_ABSENT": 10, "VERIFY_RECORD_PRESENT": 11, "VERIFY_RECORD_REDACTED": 12, "VERIFY_RECORD_ANONYMIZED": 13,
        "VERIFY_DATA_FLOW_DISABLED": 14, "VERIFY_RESTORE_BLOCKED": 15
    }
    sorted_steps = sorted([step.model_dump() for step in steps], key=lambda x: (phase_order[x['phase']], operation_order[x['operation']], x['system_id'], x['resource_id']))
    for idx, step in enumerate(sorted_steps, start=1): step['step_no'] = idx
    return sorted_steps

def main():
    print("Starting script execution...")
    data = load_data()
    requests_df = data["requests"]
    results = []
    
    for _, row in requests_df.iterrows():
        status, steps = analyze_case(row, data)
        results.append({
            "case_id": row['case_id'],
            "deletion_status": status,
            "steps_json": json.dumps(format_steps(steps))
        })
        
    output_df = pd.DataFrame(results)
    output_df.to_csv("output.csv", index=False)
    print(f"SUCCESS: Processed {len(output_df)} cases and saved to {os.path.abspath('output.csv')}")

if __name__ == "__main__":
    main()