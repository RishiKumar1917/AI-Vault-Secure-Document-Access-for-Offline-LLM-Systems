"""Role-Based Access Control (RBAC) engine for document permissioning."""

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set


@dataclass(frozen=True)
class User:
    """Represents an authenticated user and their assigned enterprise role."""
    username: str
    role: str


@dataclass(frozen=True)
class Document:
    """Represents a document within the secure vault."""
    id: str
    title: str
    content: str
    allowed_roles: Set[str]


class RBACManager:
    """Manages document-level access permissions based on user roles."""

    def __init__(self, role_permissions: Optional[Dict[str, Iterable[str]]] = None) -> None:
        """
        Initialize RBAC manager with a mapping of role -> allowed document IDs.
        
        Args:
            role_permissions: Optional dict mapping role names to collections of document IDs.
        """
        self._role_permissions: Dict[str, Set[str]] = {}
        if role_permissions:
            for role, doc_ids in role_permissions.items():
                self._role_permissions[role.lower()] = {doc_id.lower() for doc_id in doc_ids}

    def register_permission(self, role: str, document_id: str) -> None:
        """Grant a role permission to access a specific document."""
        role_key = role.lower()
        if role_key not in self._role_permissions:
            self._role_permissions[role_key] = set()
        self._role_permissions[role_key].add(document_id.lower())

    def can_access(self, role: str, document_id: str) -> bool:
        """
        Check if a given role is authorized to access a document.
        
        Args:
            role: The role name of the requesting user.
            document_id: The unique identifier of the target document.
            
        Returns:
            True if authorized, False otherwise.
        """
        role_key = role.lower()
        # Admin has access to all registered documents if explicitly configured or mapped
        if role_key == "admin" and "admin" not in self._role_permissions:
            return True
        allowed_docs = self._role_permissions.get(role_key, set())
        return document_id.lower() in allowed_docs

    def get_accessible_documents(self, role: str, all_documents: Dict[str, str]) -> Dict[str, str]:
        """
        Filter a dictionary of documents to only include those authorized for the role.
        
        Args:
            role: The role name of the requesting user.
            all_documents: Dictionary of document_id -> document_content.
            
        Returns:
            Filtered dictionary of authorized documents only.
        """
        role_key = role.lower()
        if role_key == "admin" and "admin" not in self._role_permissions:
            return all_documents.copy()
        
        allowed_ids = self._role_permissions.get(role_key, set())
        return {
            doc_id: content
            for doc_id, content in all_documents.items()
            if doc_id.lower() in allowed_ids
        }
