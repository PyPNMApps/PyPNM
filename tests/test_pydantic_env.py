
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import pydantic
import pytest
from pydantic import BaseModel, Field, ValidationError, model_validator

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv3,
)


def test_pydantic_version_supported() -> None:
    """
    Ensure that the active Pydantic version is within the expected 2.x range
    that PyPNM is known to support.
    """
    version_str = pydantic.__version__
    major_s, minor_s, *_ = version_str.split(".")
    major = int(major_s)
    minor = int(minor_s)

    # Adjust these if you later loosen/tighten your pin in pyproject.toml
    assert major == 2, f"Expected Pydantic major version 2.x, got {version_str}"
    assert minor >= 12, f"Expected Pydantic >= 2.12.x, got {version_str}"


def test_model_validator_after_instance_style() -> None:
    """
    Smoke-test that mode='after' validators work as instance methods,
    matching the pattern used in SNMPv3 and similar models.
    """

    class DemoModel(BaseModel):
        security_level: str = Field(default="noAuthNoPriv")
        auth_password: str | None = Field(default=None)

        @model_validator(mode="after")
        def _check_auth(self) -> DemoModel:
            if self.security_level.startswith("auth") and not self.auth_password:
                raise ValueError("auth_password required when using auth* security_level")
            return self

    m = DemoModel(security_level="noAuthNoPriv")
    assert m.security_level == "noAuthNoPriv"
    assert m.auth_password is None

    m2 = DemoModel(security_level="authNoPriv", auth_password="secret")
    assert m2.auth_password == "secret"

    with pytest.raises(ValidationError):
        DemoModel(security_level="authNoPriv")


def test_snmpv3_validator_basic() -> None:
    """
    Verify SNMPv3 post-init validation logic for auth/priv combinations.
    """
    # noAuthNoPriv: no auth/priv required
    SNMPv3(securityLevel="noAuthNoPriv")

    # authNoPriv: auth fields required
    with pytest.raises(ValueError):
        SNMPv3(securityLevel="authNoPriv", authProtocol=None, authPassword=None)

    SNMPv3(securityLevel="authNoPriv", authProtocol="SHA", authPassword="pw")

    # authPriv: auth + priv required
    with pytest.raises(ValueError):
        SNMPv3(
            securityLevel="authPriv",
            authProtocol="SHA",
            authPassword="pw",
            privProtocol=None,
            privPassword=None,
        )

    SNMPv3(
        securityLevel="authPriv",
        authProtocol="SHA",
        authPassword="pw",
        privProtocol="AES",
        privPassword="pw2",
    )


def test_field_default_and_required_behavior() -> None:
    """
    Ensure Field(...) required/optional semantics behave as expected.
    """

    class FieldDefaultsModel(BaseModel):
        required_value: int = Field(..., description="Required integer value")
        optional_value: int | None = Field(default=None, description="Optional integer value")
        with_default: int = Field(default=10, description="Integer with default")

    # Missing required_value should fail
    with pytest.raises(ValidationError):
        FieldDefaultsModel()

    m = FieldDefaultsModel(required_value=5)
    assert m.required_value == 5
    assert m.optional_value is None
    assert m.with_default == 10


def test_field_metadata_description_and_alias() -> None:
    """
    Validate that Field(...) metadata (description, alias) is stored and respected
    in both parsing and dumping.
    """

    class FieldMetadataModel(BaseModel):
        value: int = Field(default=1, description="Some integer value", alias="val")

    # Input using alias
    m = FieldMetadataModel(val=7)
    assert m.value == 7

    # Dump using aliases
    dumped = m.model_dump(by_alias=True)
    assert dumped == {"val": 7}

    # Confirm description is present in model_fields metadata
    field_info = FieldMetadataModel.model_fields["value"]
    assert field_info.description == "Some integer value"


def test_field_default_factory_behavior() -> None:
    """
    Ensure Field(default_factory=...) works as expected and generates fresh values.
    """

    counter = {"calls": 0}

    def _factory() -> int:
        counter["calls"] += 1
        return 100 + counter["calls"]

    class FactoryModel(BaseModel):
        seq: int = Field(default_factory=_factory, description="Sequence with default_factory")

    m1 = FactoryModel()
    m2 = FactoryModel()

    # Each instance should get a different value from the factory
    assert m1.seq == 101
    assert m2.seq == 102
    assert counter["calls"] == 2

def test_field_validator_basic() -> None:
    """Test basic functionality of field validators in Pydantic models."""

    class ValidatorModel(BaseModel):
        name: str = Field(default="default_name")

        @pydantic.field_validator("name")
        def name_must_not_be_blank(cls, v: str) -> str:
            if not v.strip():
                raise ValueError("name must not be blank")
            return v

    # Valid name
    m = ValidatorModel(name="valid_name")
    assert m.name == "valid_name"

    # Blank name should raise ValueError
    with pytest.raises(ValidationError):
        ValidatorModel(name="   ")
