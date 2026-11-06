import csv
import io

def export_alerts_to_csv(alerts):
    """
    Converts a list of alert dictionaries into a CSV string.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "Alert ID", 
        "Timestamp", 
        "Alert Type", 
        "Source IP", 
        "Destination IP", 
        "Description", 
        "Severity", 
        "Status"
    ])
    
    # Write rows
    for alert in alerts:
        status = "Resolved" if alert.get("resolved") == 1 else "Unresolved"
        writer.writerow([
            alert.get("id"),
            alert.get("timestamp"),
            alert.get("alert_type"),
            alert.get("source_ip"),
            alert.get("dest_ip"),
            alert.get("description"),
            alert.get("severity"),
            status
        ])
        
    return output.getvalue()
