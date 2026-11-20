"""Error classification helpers.

Provides `ErrorClassifier` to categorize exceptions and recommend actions.
"""
from typing import Dict
import requests


class ErrorClassifier:
    """Classify errors for better handling and retry decisions."""
    
    @staticmethod
    def classify_error(error: Exception) -> Dict:
        """
        Classify error type and suggest handling strategy.
        
        Returns:
            Dict with 'category', 'retryable', 'action', 'recommendation'
        """
        error_str = str(error).lower()
        
        # Network errors
        if isinstance(error, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            return {
                'category': 'network',
                'retryable': True,
                'action': 'retry_with_backoff',
                'recommendation': 'Check network connectivity and try again'
            }
        
        # Authentication errors
        if isinstance(error, requests.exceptions.HTTPError) and getattr(getattr(error, 'response', None), 'status_code', None) == 401:
            return {
                'category': 'authentication',
                'retryable': True,
                'action': 'refresh_token',
                'recommendation': 'Token expired or invalid, refreshing'
            }
        
        # Rate limiting
        if isinstance(error, requests.exceptions.HTTPError) and getattr(getattr(error, 'response', None), 'status_code', None) == 429:
            return {
                'category': 'rate_limit',
                'retryable': True,
                'action': 'wait_and_retry',
                'recommendation': 'Rate limited, backing off'
            }
        
        # Conditional Access
        if 'conditional access' in error_str or 'mfa required' in error_str:
            return {
                'category': 'conditional_access',
                'retryable': False,
                'action': 'reauth_required',
                'recommendation': 'Conditional Access policy requires reauthentication'
            }
        
        # Fatal authentication errors that mean the refresh token is dead.
        fatal_patterns = [
            'aadsts9002313',
            'aadsts700025',
            'aadsts700082',
            'aadsts700084',
            'aadsts700081',
            'aadsts50173',
            'aadsts54005',
            'invalid_client',
            'unauthorized_client',
            'invalid_request',
            'invalid_grant',
        ]
        if any(pattern in error_str for pattern in fatal_patterns):
            return {
                'category': 'authentication',
                'retryable': False,
                'action': 'abort',
                'recommendation': 'Refresh token is dead. Removing from store.'
            }
        
        # Unknown
        return {
            'category': 'unknown',
            'retryable': True,
            'action': 'retry_with_backoff',
            'recommendation': 'Unknown error, retrying with backoff'
        }
