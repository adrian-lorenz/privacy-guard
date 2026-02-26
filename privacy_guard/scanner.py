from __future__ import annotations
from .models import Finding, PiiType, ScanResult
from .whitelist import WhitelistManager
from .detectors.base import BaseDetector
from .detectors.iban import IbanDetector
from .detectors.phone import PhoneDetector
from .detectors.email import EmailDetector
from .detectors.name import NameDetector
from .detectors.address import AddressDetector
from .detectors.credit_card import CreditCardDetector
from .detectors.personal_id import PersonalIdDetector
from .detectors.social_security import SocialSecurityDetector
from .detectors.tax_id import TaxIdDetector
from .detectors.url_secret import UrlSecretDetector
from .detectors.secret import SecretDetector

# Priority: higher wins when spans overlap
_PRIORITY: dict[PiiType, int] = {
    PiiType.SECRET: 6,
    PiiType.URL_SECRET: 6,
    PiiType.IBAN: 5,
    PiiType.CREDIT_CARD: 5,
    PiiType.SOCIAL_SECURITY: 5,
    PiiType.PERSONAL_ID: 4,
    PiiType.TAX_ID: 4,
    PiiType.EMAIL: 4,
    PiiType.PHONE: 3,
    PiiType.ADDRESS: 2,
    PiiType.NAME: 1,
}


def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Left-to-right sweep; on overlap keep the higher-priority (or longer) finding."""
    # Sort by start, then by descending priority, then by descending length
    sorted_findings = sorted(
        findings,
        key=lambda f: (f.start, -_PRIORITY[f.pii_type], -(f.end - f.start)),
    )

    result: list[Finding] = []
    last_end = -1

    for finding in sorted_findings:
        if finding.start >= last_end:
            result.append(finding)
            last_end = finding.end
        else:
            # Overlap — compare with the last accepted finding
            prev = result[-1]
            prev_priority = _PRIORITY[prev.pii_type]
            curr_priority = _PRIORITY[finding.pii_type]
            if curr_priority > prev_priority or (
                curr_priority == prev_priority and len(finding) > len(prev)
            ):
                result[-1] = finding
                last_end = finding.end

    return result


class PrivacyScanner:
    def __init__(
        self,
        whitelist: WhitelistManager | None = None,
        extra_whitelist_names: list[str] | None = None,
    ) -> None:
        wl = whitelist or WhitelistManager(extra_names=extra_whitelist_names)
        self._whitelist = wl
        self._detectors: dict[PiiType, BaseDetector] = {
            PiiType.SECRET: SecretDetector(),
            PiiType.URL_SECRET: UrlSecretDetector(),
            PiiType.IBAN: IbanDetector(),
            PiiType.CREDIT_CARD: CreditCardDetector(),
            PiiType.SOCIAL_SECURITY: SocialSecurityDetector(),
            PiiType.PERSONAL_ID: PersonalIdDetector(),
            PiiType.TAX_ID: TaxIdDetector(),
            PiiType.EMAIL: EmailDetector(),
            PiiType.PHONE: PhoneDetector(),
            PiiType.NAME: NameDetector(whitelist=wl),
            PiiType.ADDRESS: AddressDetector(),
        }
        self._disabled: set[PiiType] = set()

    def disable_detector(self, pii_type: PiiType) -> None:
        self._disabled.add(pii_type)

    def enable_detector(self, pii_type: PiiType) -> None:
        self._disabled.discard(pii_type)

    def scan(self, text: str) -> ScanResult:
        all_findings: list[Finding] = []

        for pii_type, detector in self._detectors.items():
            if pii_type in self._disabled:
                continue
            all_findings.extend(detector.detect(text))

        # Resolve overlapping spans
        resolved = _resolve_overlaps(all_findings)

        # Build deduplicated placeholder mapping and renumber
        text_to_placeholder: dict[str, str] = {}
        type_counters: dict[str, int] = {}
        final_findings: list[Finding] = []

        for finding in resolved:
            original = finding.text
            if original in text_to_placeholder:
                # Reuse existing placeholder
                placeholder = text_to_placeholder[original]
            else:
                key = finding.pii_type.value
                type_counters[key] = type_counters.get(key, 0) + 1
                placeholder = f"[{key}_{type_counters[key]}]"
                text_to_placeholder[original] = placeholder

            final_findings.append(
                Finding(
                    pii_type=finding.pii_type,
                    start=finding.start,
                    end=finding.end,
                    text=original,
                    confidence=finding.confidence,
                    placeholder=placeholder,
                    rule_id=finding.rule_id,
                )
            )

        # Build mapping: placeholder → original
        mapping: dict[str, str] = {v: k for k, v in text_to_placeholder.items()}

        # Build anonymised text (process in reverse order to keep positions valid)
        anonymised = text
        for finding in sorted(final_findings, key=lambda f: f.start, reverse=True):
            anonymised = (
                anonymised[: finding.start]
                + finding.placeholder
                + anonymised[finding.end :]
            )

        return ScanResult(
            original_text=text,
            anonymised_text=anonymised,
            findings=final_findings,
            mapping=mapping,
        )
