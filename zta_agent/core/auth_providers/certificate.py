"""
Certificate-based Authentication Provider
"""

from typing import Dict, Optional, Tuple
import ssl
import OpenSSL.crypto
from datetime import datetime
from .base import AuthenticationProvider

class CertificateProvider(AuthenticationProvider):
    """Certificate-based authentication provider"""
    
    def __init__(self, config: Dict):
        """
        Initialize certificate provider with configuration
        
        Config should include:
        - ca_cert_path: Path to CA certificate
        - ca_key_path: Path to CA private key (optional)
        - allowed_subjects: List of allowed certificate subject patterns
        - verify_crl: Whether to check Certificate Revocation List
        - crl_path: Path to CRL file (if verify_crl is True)
        """
        self.config = config
        self.ca_cert_path = config["ca_cert_path"]
        self.verify_crl = config.get("verify_crl", False)
        self.crl_path = config.get("crl_path")
        self.allowed_subjects = config.get("allowed_subjects", [])
        
        # Load CA certificate
        with open(self.ca_cert_path, 'rb') as f:
            self.ca_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, f.read()
            )

        # Load CRL if configured
        self.crl = None
        if self.verify_crl and self.crl_path:
            with open(self.crl_path, 'rb') as f:
                self.crl = OpenSSL.crypto.load_crl(
                    OpenSSL.crypto.FILETYPE_PEM, f.read()
                )

    def verify_certificate(self, cert_data: bytes) -> Tuple[bool, str]:
        """
        Verify a certificate against the CA and CRL
        
        Args:
            cert_data: Certificate data in PEM format
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        try:
            # Load client certificate
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert_data
            )
            
            # Check expiration
            not_after = datetime.strptime(
                cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
            )
            if datetime.utcnow() > not_after:
                return False, "Certificate has expired"

            # Verify against CA
            store = OpenSSL.crypto.X509Store()
            store.add_cert(self.ca_cert)
            
            # Add CRL if configured
            if self.verify_crl and self.crl:
                store.add_crl(self.crl)
                store.set_flags(OpenSSL.crypto.X509StoreFlags.CRL_CHECK)

            # Create store context
            store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)
            
            # Verify certificate
            try:
                store_ctx.verify_certificate()
            except OpenSSL.crypto.X509StoreContextError as e:
                return False, f"Certificate verification failed: {str(e)}"

            # Check subject pattern
            if self.allowed_subjects:
                subject = cert.get_subject()
                subject_str = str(subject)
                if not any(pattern in subject_str for pattern in self.allowed_subjects):
                    return False, "Certificate subject not allowed"

            return True, ""
        except Exception as e:
            return False, f"Certificate validation error: {str(e)}"

    def extract_identity(self, cert_data: bytes) -> Optional[Dict]:
        """
        Extract identity information from certificate
        
        Args:
            cert_data: Certificate data in PEM format
            
        Returns:
            Optional[Dict]: Identity information from certificate
        """
        try:
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert_data
            )
            subject = cert.get_subject()
            
            return {
                "identity": str(subject.CN),  # Common Name as identity
                "organization": str(subject.O),
                "organizational_unit": str(subject.OU),
                "email": str(subject.emailAddress),
                "provider": "certificate",
                "certificate_serial": str(cert.get_serial_number()),
                "valid_from": datetime.strptime(
                    cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'
                ).isoformat(),
                "valid_until": datetime.strptime(
                    cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
                ).isoformat()
            }
        except Exception:
            return None

    def authenticate(self, credentials: Dict) -> Optional[Dict]:
        """
        Authenticate using client certificate
        
        Args:
            credentials: Dictionary containing:
                - certificate: Client certificate in PEM format
            
        Returns:
            Optional[Dict]: Identity information if authentication successful
        """
        cert_data = credentials.get("certificate")
        if not cert_data:
            return None

        # Verify certificate
        is_valid, error = self.verify_certificate(cert_data)
        if not is_valid:
            return None

        # Extract identity information
        return self.extract_identity(cert_data)

    def validate_credentials(self, credentials: Dict) -> Tuple[bool, str]:
        """
        Validate certificate credentials format
        
        Args:
            credentials: Dictionary containing certificate data
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if "certificate" not in credentials:
            return False, "Client certificate is required"
        
        try:
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, credentials["certificate"]
            )
            return True, ""
        except Exception as e:
            return False, f"Invalid certificate format: {str(e)}"
