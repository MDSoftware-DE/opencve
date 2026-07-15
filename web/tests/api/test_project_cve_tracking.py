from types import SimpleNamespace
from unittest.mock import patch

import pytest

from organizations.models import OrganizationAPIToken
from projects.models import CveComment, CveTracker


TRACKER_STATUSES = [
    "to_evaluate",
    "pending_review",
    "analysis_in_progress",
    "remediation_in_progress",
    "evaluated",
    "resolved",
    "not_applicable",
    "risk_accepted",
]
CASE_URL = "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42"


@pytest.fixture
def tracking_case(
    client,
    create_cve,
    create_organization,
    create_project,
    create_user,
):
    user = create_user(username="secops-api")
    organization = create_organization(name="md-software", user=user)
    project = create_project(
        name="colossus",
        organization=organization,
        vendors=["siemens"],
    )
    cve = create_cve("CVE-2021-44228")
    token = OrganizationAPIToken.create_token(
        organization=organization,
        name="SecOps writeback",
        description=None,
        created_by=user,
    )
    return SimpleNamespace(
        client=client,
        user=user,
        organization=organization,
        project=project,
        cve=cve,
        token=token,
    )


def tracking_url(case, *, organization=None, project=None, cve_id=None):
    organization = organization or case.organization.name
    project = project or case.project.name
    cve_id = cve_id or case.cve.cve_id
    return (
        f"/api/organizations/{organization}/projects/{project}"
        f"/cve/{cve_id}/tracking"
    )


def tracking_payload(
    *,
    event_id="ops-triage:CVE-2021-44228:github:42:resolved:v1",
    status="resolved",
    comment=f"SecOps case resolved: {CASE_URL}",
    case_url=CASE_URL,
):
    return {
        "event_id": event_id,
        "status": status,
        "comment": comment,
        "case_url": case_url,
    }


def patch_tracking(case, payload, *, token=None, url=None):
    return case.client.patch(
        url or tracking_url(case),
        data=payload,
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {token or case.token}",
    )


def get_tracking(case, *, token=None, url=None):
    return case.client.get(
        url or tracking_url(case),
        HTTP_AUTHORIZATION=f"Bearer {token or case.token}",
    )


@pytest.mark.django_db
def test_tracking_requires_authentication(tracking_case):
    response = tracking_case.client.get(tracking_url(tracking_case))

    assert response.status_code == 401


@pytest.mark.django_db
def test_tracking_rejects_other_organization_token(
    tracking_case,
    create_organization,
    create_user,
):
    other_user = create_user(username="other-secops")
    other_organization = create_organization(name="other-org", user=other_user)
    other_token = OrganizationAPIToken.create_token(
        organization=other_organization,
        name="Other token",
        description=None,
        created_by=other_user,
    )

    response = get_tracking(tracking_case, token=other_token)

    assert response.status_code == 404


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("url_factory", "expected_status"),
    [
        (lambda case: tracking_url(case, project="unknown-project"), 404),
        (lambda case: tracking_url(case, cve_id="not-a-cve"), 404),
    ],
)
def test_tracking_rejects_unknown_nested_resources(
    tracking_case,
    url_factory,
    expected_status,
):
    response = get_tracking(tracking_case, url=url_factory(tracking_case))

    assert response.status_code == expected_status


@pytest.mark.django_db
def test_tracking_rejects_unsubscribed_cve(tracking_case, create_project):
    project = create_project(
        name="unsubscribed",
        organization=tracking_case.organization,
        vendors=["vendor-not-present-on-cve"],
    )

    response = get_tracking(
        tracking_case,
        url=tracking_url(tracking_case, project=project.name),
    )

    assert response.status_code == 404


@pytest.mark.django_db
def test_tracking_get_without_events_returns_current_empty_state(tracking_case):
    response = get_tracking(tracking_case)

    assert response.status_code == 200
    assert response.json() == {
        "cve_id": tracking_case.cve.cve_id,
        "status": None,
        "case_url": None,
        "event_id": None,
    }


@pytest.mark.django_db
@pytest.mark.parametrize("status", TRACKER_STATUSES)
def test_tracking_accepts_every_tracker_status(tracking_case, status):
    event_id = f"ops-triage:{tracking_case.cve.cve_id}:{status}:v1"
    payload = tracking_payload(event_id=event_id, status=status)

    response = patch_tracking(tracking_case, payload)

    assert response.status_code == 200
    assert response.json() == {
        "cve_id": tracking_case.cve.cve_id,
        "status": status,
        "case_url": CASE_URL,
        "event_id": event_id,
        "created": True,
    }
    tracker = CveTracker.objects.get(
        project=tracking_case.project,
        cve=tracking_case.cve,
    )
    assert tracker.status == status
    assert CveComment.objects.filter(
        project=tracking_case.project,
        cve=tracking_case.cve,
        author=tracking_case.user,
    ).count() == 1


@pytest.mark.django_db
def test_tracking_is_idempotent_and_detects_event_conflicts(tracking_case):
    payload = tracking_payload()

    first = patch_tracking(tracking_case, payload)
    retry = patch_tracking(tracking_case, payload)
    conflict = patch_tracking(
        tracking_case,
        tracking_payload(status="risk_accepted"),
    )

    assert first.status_code == 200
    assert first.json()["created"] is True
    assert retry.status_code == 200
    assert retry.json() == {**first.json(), "created": False}
    assert conflict.status_code == 409
    assert CveComment.objects.filter(
        project=tracking_case.project,
        cve=tracking_case.cve,
    ).count() == 1

    tracker = CveTracker.objects.get(
        project=tracking_case.project,
        cve=tracking_case.cve,
    )
    assert tracker.status == "resolved"

    event_model = tracker.cve.tracking_events.model
    assert event_model.objects.filter(
        project=tracking_case.project,
        cve=tracking_case.cve,
    ).count() == 1

    current = get_tracking(tracking_case)
    assert current.status_code == 200
    assert current.json() == {
        "cve_id": tracking_case.cve.cve_id,
        "status": "resolved",
        "case_url": CASE_URL,
        "event_id": payload["event_id"],
    }


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("payload", "field"),
    [
        (
            {
                "status": "resolved",
                "comment": f"SecOps case resolved: {CASE_URL}",
                "case_url": CASE_URL,
            },
            "event_id",
        ),
        (tracking_payload(event_id="x" * 129), "event_id"),
        (tracking_payload(status="unknown"), "status"),
        (tracking_payload(comment=""), "comment"),
    ],
)
def test_tracking_rejects_invalid_required_fields(tracking_case, payload, field):
    response = patch_tracking(tracking_case, payload)

    assert response.status_code == 400
    assert field in response.json()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "case_url",
    [
        "http://github.com/MDSoftware-DE/vps-colossus-config/issues/42",
        "https://example.com/MDSoftware-DE/vps-colossus-config/issues/42",
        "https://user@github.com/MDSoftware-DE/vps-colossus-config/issues/42",
        "https://github.com:443/MDSoftware-DE/vps-colossus-config/issues/42",
        "https://github.com/OtherOwner/vps-colossus-config/issues/42",
        "https://github.com/MDSoftware-DE/vps-colossus-config/pull/42",
        "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42?x=1",
        "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42#comment",
    ],
)
def test_tracking_restricts_case_url_to_mdsoftware_github_issues(
    tracking_case,
    case_url,
):
    response = patch_tracking(
        tracking_case,
        tracking_payload(case_url=case_url),
    )

    assert response.status_code == 400
    assert "case_url" in response.json()


@pytest.mark.django_db
def test_tracking_enforces_comment_length_boundary(tracking_case):
    accepted = patch_tracking(
        tracking_case,
        tracking_payload(
            event_id="comment-boundary-accepted",
            comment="x" * 4096,
        ),
    )
    rejected = patch_tracking(
        tracking_case,
        tracking_payload(
            event_id="comment-boundary-rejected",
            comment="x" * 4097,
        ),
    )

    assert accepted.status_code == 200
    assert rejected.status_code == 400
    assert "comment" in rejected.json()


@pytest.mark.django_db
def test_tracking_rolls_back_status_when_comment_creation_fails(tracking_case):
    tracker = CveTracker.objects.create(
        project=tracking_case.project,
        cve=tracking_case.cve,
        status="pending_review",
    )

    with patch(
        "projects.resources.CveComment.objects.create",
        side_effect=RuntimeError("comment write failed"),
    ):
        with pytest.raises(RuntimeError, match="comment write failed"):
            patch_tracking(tracking_case, tracking_payload())

    tracker.refresh_from_db()
    assert tracker.status == "pending_review"
    assert CveComment.objects.filter(
        project=tracking_case.project,
        cve=tracking_case.cve,
    ).count() == 0
