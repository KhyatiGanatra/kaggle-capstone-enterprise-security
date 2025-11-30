"""BigQuery-based persistent memory for agents"""

import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from google.cloud import bigquery
from google.api_core import exceptions as google_exceptions

logger = logging.getLogger(__name__)


def is_gcp_environment() -> bool:
    """Quick check if running in GCP (has credentials configured)"""
    # Check for explicit credentials or GCP environment indicators
    return (
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS") is not None or
        os.getenv("GOOGLE_CLOUD_PROJECT") is not None and 
        os.path.exists("/var/run/secrets/kubernetes.io") or  # GKE
        os.getenv("K_SERVICE") is not None  # Cloud Run
    )


class ThreatIntelMemory:
    """Memory storage for Threat Analysis Agent using BigQuery"""
    
    def __init__(self, project_id: str):
        # Fast-fail if not in GCP environment (avoids 3s timeout)
        if not is_gcp_environment():
            raise RuntimeError("Not in GCP environment - BigQuery unavailable (this is expected in Streamlit Cloud)")
        
        self.project_id = project_id
        self.bq_client = bigquery.Client(project=project_id)
        self.dataset_id = "security_intel"
        self.table_id = "threat_intelligence"
        self.full_table_id = f"{project_id}.{self.dataset_id}.{self.table_id}"
    
    def store_threat_analysis(self, analysis: dict) -> bool:
        """Store threat analysis results in BigQuery"""
        try:
            # Add metadata
            analysis['analyzed_at'] = datetime.now().isoformat()
            analysis['agent'] = 'ThreatAnalysisAgent'
            
            rows_to_insert = [analysis]
            errors = self.bq_client.insert_rows_json(self.full_table_id, rows_to_insert)
            
            if errors:
                logger.error(f"Error storing threat analysis: {errors}")
                return False
            
            logger.info(f"✓ Stored threat analysis for {analysis.get('indicator')}")
            return True
            
        except Exception as e:
            logger.error(f"Exception storing threat analysis: {e}")
            return False
    
    def retrieve_threat_history(self, indicator: str, days_back: int = 30) -> List[dict]:
        """Retrieve historical threat intelligence for an indicator"""
        query = f"""
            SELECT 
                indicator,
                indicator_type,
                threat_type,
                severity,
                confidence,
                source,
                mitre_techniques,
                first_seen,
                last_seen,
                analyzed_at
            FROM `{self.full_table_id}`
            WHERE indicator = @indicator
              AND analyzed_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days_back DAY)
            ORDER BY analyzed_at DESC
            LIMIT 10
        """
        
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("indicator", "STRING", indicator),
                bigquery.ScalarQueryParameter("days_back", "INT64", days_back)
            ]
        )
        
        try:
            results = self.bq_client.query(query, job_config=job_config)
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Error retrieving threat history: {e}")
            return []
    
    def get_recent_threats(self, hours: int = 24, severity: str = None) -> List[dict]:
        """Get recent threats detected in the specified time window"""
        query = f"""
            SELECT *
            FROM `{self.full_table_id}`
            WHERE analyzed_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @hours HOUR)
        """
        
        if severity:
            query += " AND severity = @severity"
        
        query += " ORDER BY analyzed_at DESC LIMIT 100"
        
        params = [bigquery.ScalarQueryParameter("hours", "INT64", hours)]
        if severity:
            params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity))
        
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        
        try:
            results = self.bq_client.query(query, job_config=job_config)
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Error retrieving recent threats: {e}")
            return []
