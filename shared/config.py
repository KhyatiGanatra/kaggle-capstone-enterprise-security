"""Configuration for Google Cloud Security MCP Servers"""

import os
import logging

logger = logging.getLogger(__name__)


class GoogleSecurityMCPConfig:
    """Configuration for Google Cloud Security MCP Servers"""
    
    @staticmethod
    def _get_env(key, default=None):
        val = os.getenv(key, default)
        if not val and default is None:
            logger.warning(f"Environment variable {key} is missing. Dependent MCP servers may fail.")
        return val

    @property
    def CHRONICLE_SECOPS(self):
        return {
            "name": "chronicle_secops",
            "command": "uvx",
            "args": ["--from", "google-secops-mcp", "secops_mcp"],
            "env": {
                "CHRONICLE_PROJECT_ID": self._get_env("CHRONICLE_PROJECT_ID", "your-project-id"),
                "CHRONICLE_CUSTOMER_ID": self._get_env("CHRONICLE_CUSTOMER_ID", "your-customer-id"),
                "CHRONICLE_REGION": self._get_env("CHRONICLE_REGION", "us"),
            }
        }
    
    @property
    def CHRONICLE_SOAR(self):
        return {
            "name": "chronicle_soar",
            "command": "uvx",
            "args": ["secops_soar_mcp", "--integrations", "CSV,OKTA"],
            "env": {
                "SOAR_URL": self._get_env("SOAR_URL", "https://your-tenant.siemplify-soar.com:443"),
                "SOAR_APP_KEY": self._get_env("SOAR_APP_KEY", "your-soar-api-key"),
            }
        }
    
    @property
    def GOOGLE_THREAT_INTEL(self):
        return {
            "name": "gti",
            "command": "uvx",
            "args": ["gti_mcp"],
            "env": {
                "VT_APIKEY": self._get_env("VT_APIKEY", "your-virustotal-api-key"),
            }
        }
    
    @property
    def SECURITY_COMMAND_CENTER(self):
        return {
            "name": "scc",
            "command": "uvx",
            "args": ["scc_mcp"],
            "env": {
                "GOOGLE_CLOUD_PROJECT": self._get_env("GOOGLE_CLOUD_PROJECT", "your-project-id"),
            }
        }





