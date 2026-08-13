"""Unit tests for Role-Based Access Control (RBAC)."""

import pytest
from gateway.rbac import RBACManager, User


def test_rbac_authorization_success():
    manager = RBACManager({
        "intern": ["public_handbook"],
        "engineer": ["public_handbook", "engineering_specs"],
        "hr": ["public_handbook", "payroll_q3"],
    })

    assert manager.can_access("intern", "public_handbook") is True
    assert manager.can_access("engineer", "engineering_specs") is True
    assert manager.can_access("hr", "payroll_q3") is True


def test_rbac_authorization_denied():
    manager = RBACManager({
        "intern": ["public_handbook"],
        "engineer": ["public_handbook", "engineering_specs"],
        "hr": ["public_handbook", "payroll_q3"],
    })

    assert manager.can_access("intern", "payroll_q3") is False
    assert manager.can_access("intern", "engineering_specs") is False
    assert manager.can_access("engineer", "payroll_q3") is False


def test_rbac_filter_documents():
    manager = RBACManager({
        "intern": ["public_handbook"],
        "hr": ["public_handbook", "payroll_q3"],
    })
    all_docs = {
        "public_handbook": "Public Content",
        "engineering_specs": "Engineering Content",
        "payroll_q3": "Payroll Content"
    }

    intern_docs = manager.get_accessible_documents("intern", all_docs)
    assert "public_handbook" in intern_docs
    assert "payroll_q3" not in intern_docs
    assert "engineering_specs" not in intern_docs

    hr_docs = manager.get_accessible_documents("hr", all_docs)
    assert "public_handbook" in hr_docs
    assert "payroll_q3" in hr_docs
    assert "engineering_specs" not in hr_docs
