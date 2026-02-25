from .base import BaseDetector
from .iban import IbanDetector
from .phone import PhoneDetector
from .email import EmailDetector
from .name import NameDetector
from .address import AddressDetector

__all__ = [
    "BaseDetector",
    "IbanDetector",
    "PhoneDetector",
    "EmailDetector",
    "NameDetector",
    "AddressDetector",
]
