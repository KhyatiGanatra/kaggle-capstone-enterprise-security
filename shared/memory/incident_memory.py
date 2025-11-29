"""BigQuery-based persistent memory for agents"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from google.cloud import bigquery
from google.api_core import exceptions as google_exceptions

logger = logging.getLogger(__name__)

class IncidentMemory:
    """Memory storage for Incident Response Agent using BigQuery"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.bq_client = bigquery.Client(project=project_id)
        self.dataset_id = "security_intel"
        self.table_id = "active_incidents"
        self.full_table_id = f"{project_id}.{self.dataset_id}.{self.table_id}"
    
    def store_incident(self, incident: dict) -> bool:
        """Store incident information in BigQuery"""
        try:
            incident['created_at'] = incident.get('created_at', datetime.now().isoformat())
            incident['updated_at'] = datetime.now().isoformat()
            
            rows_to_insert = [incident]
            errors = self.bq_client.insert_rows_json(self.full_table_id, rows_to_insert)
            
            if errors:
                logger.error(f"Error storing incident: {errors}")
                return False
            
            logger.info(f"✓ Stored incident {incident.get('incident_id')}")
            return True
            
        except Exception as e:
            logger.error(f"Exception storing incident: {e}")
            return False
    
    def get_active_incidents(self, severity: str = None) -> List[dict]:
        """Retrieve all active incidents"""
        query = f"""
            SELECT *
            FROM `{self.full_table_id}`
            WHERE status IN ('OPEN', 'IN_PROGRESS', 'INVESTIGATING')
        """
        
        if severity:
            query += " AND severity = @severity"
        
        query += " ORDER BY severity DESC, created_at DESC"
        
        params = []
        if severity:
            params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity))
        
        job_config = bigquery.QueryJobConfig(query_parameters=params) if params else None
        
        try:
            results = self.bq_client.query(query, job_config=job_config)
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Error retrieving active incidents: {e}")
            return []
    
    def update_incident_status(self, incident_id: str, status: str, notes: str = None) -> bool:
        """Update incident status"""
        query = f"""
            UPDATE `{self.full_table_id}`
            SET status = @status,
                updated_at = CURRENT_TIMESTAMP()
            WHERE incident_id = @incident_id
        """
        
        params = [
            bigquery.ScalarQueryParameter("status", "STRING", status),
            bigquery.ScalarQueryParameter("incident_id", "STRING", incident_id)
        ]
        
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        
        try:
            self.bq_client.query(query, job_config=job_config)
            logger.info(f"✓ Updated incident {incident_id} to status: {status}")
            return True
        except Exception as e:
            logger.error(f"Error updating incident: {e}")
            return False





