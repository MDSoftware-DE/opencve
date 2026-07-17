from unittest.mock import patch

import pytest
from django.template import Context, Template

from opencve.api.v2.scopes import APIScope
from organizations.models import OrganizationAPIToken
from projects.models import CveComment, CveTracker, CveTrackerEvent


STATUSES = [choice[0] for choice in CveTracker.STATUS_CHOICES]
CASE_URL = "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42"


def _url(organization="secops", project="secops-fleet", cve_id="CVE-2021-44228"):
    return (
        f"/api/v2/organizations/{organization}/projects/{project}/cves/"
        f"{cve_id}/tracking"
    )


@pytest.fixture
def tracking_context(
    client, create_user, create_organization, create_project, create_cve
):
    user = create_user(username="secops-bot")
    organization = create_organization(name="secops", user=user)
    project = create_project(
        name="secops-fleet", organization=organization, vendors=["siemens"]
    )
    cve = create_cve("CVE-2021-44228")
    token = OrganizationAPIToken.create_token(
        organization=organization,
        name="SecOps",
        description=None,
        created_by=user,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=[APIScope.TRACKER_WRITE.value],
    )
    return {
        "client": client,
        "user": user,
        "organization": organization,
        "project": project,
        "cve": cve,
        "token": token,
        "headers": {"HTTP_AUTHORIZATION": f"Bearer {token}"},
    }


def _payload(status="analysis_in_progress", event_id="ops-triage:event-1"):
    return {
        "event_id": event_id,
        "status": status,
        "comment": f"SecOps status: {status}. Authoritative case: {CASE_URL}",
        "case_url": CASE_URL,
    }


@pytest.mark.django_db
@pytest.mark.parametrize("status", STATUSES)
def test_tracking_accepts_all_tracker_statuses(tracking_context, status):
    response = tracking_context["client"].patch(
        _url(),
        _payload(status=status, event_id=f"ops-triage:{status}"),
        content_type="application/json",
        **tracking_context["headers"],
    )

    assert response.status_code == 200
    assert response.json() == {
        "cve_id": "CVE-2021-44228",
        "status": status,
        "case_url": CASE_URL,
        "event_id": f"ops-triage:{status}",
        "created": True,
    }
    tracker = CveTracker.objects.get(
        project=tracking_context["project"], cve=tracking_context["cve"]
    )
    assert tracker.status == status


@pytest.mark.django_db
def test_tracking_identical_retry_is_idempotent_and_conflict_is_explicit(
    tracking_context,
):
    first = tracking_context["client"].patch(
        _url(),
        _payload(),
        content_type="application/json",
        **tracking_context["headers"],
    )
    retry = tracking_context["client"].patch(
        _url(),
        _payload(),
        content_type="application/json",
        **tracking_context["headers"],
    )
    conflict = tracking_context["client"].patch(
        _url(),
        _payload(status="resolved"),
        content_type="application/json",
        **tracking_context["headers"],
    )

    assert first.status_code == 200
    assert first.json()["created"] is True
    assert retry.status_code == 200
    assert retry.json()["created"] is False
    assert conflict.status_code == 409
    assert CveTrackerEvent.objects.count() == 1
    assert CveComment.objects.count() == 1


@pytest.mark.django_db
def test_tracking_is_organization_scoped_and_requires_subscription(
    tracking_context, create_organization, create_project
):
    other = create_organization(name="other")
    create_project(name="secops-fleet", organization=other, vendors=["siemens"])
    unsubscribed = create_project(
        name="unsubscribed", organization=tracking_context["organization"]
    )

    cross_org = tracking_context["client"].patch(
        _url(organization="other"),
        _payload(),
        content_type="application/json",
        **tracking_context["headers"],
    )
    not_subscribed = tracking_context["client"].patch(
        _url(project=unsubscribed.name),
        _payload(),
        content_type="application/json",
        **tracking_context["headers"],
    )
    unauthenticated = tracking_context["client"].patch(
        _url(), _payload(), content_type="application/json"
    )

    assert cross_org.status_code == 404
    assert not_subscribed.status_code == 404
    assert unauthenticated.status_code == 401


@pytest.mark.django_db
def test_tracking_requires_write_token_tracker_scope_and_actor(
    tracking_context, settings
):
    client = tracking_context["client"]
    organization = tracking_context["organization"]
    user = tracking_context["user"]

    read_token = OrganizationAPIToken.create_token(
        organization=organization,
        name="Read only",
        description=None,
        created_by=user,
    )
    read_only = client.patch(
        _url(),
        _payload(),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {read_token}",
    )

    settings.API_SCOPES_ENABLED = True
    wrong_scope_token = OrganizationAPIToken.create_token(
        organization=organization,
        name="Wrong scope",
        description=None,
        created_by=user,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=[APIScope.PROJECTS_READ.value],
    )
    wrong_scope = client.patch(
        _url(),
        _payload(),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {wrong_scope_token}",
    )

    no_actor_token = OrganizationAPIToken.create_token(
        organization=organization,
        name="No actor",
        description=None,
        created_by=None,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=[APIScope.TRACKER_WRITE.value],
    )
    no_actor = client.patch(
        _url(),
        _payload(),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {no_actor_token}",
    )

    assert read_only.status_code == 403
    assert wrong_scope.status_code == 403
    assert no_actor.status_code == 403
    assert not CveTracker.objects.exists()
    assert not CveComment.objects.exists()
    assert not CveTrackerEvent.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "changes",
    [
        {"event_id": ""},
        {"event_id": "x" * 129},
        {"status": "closed"},
        {"comment": ""},
        {"comment": "x" * 10001},
        {"case_url": "http://github.com/MDSoftware-DE/repo/issues/1"},
        {"case_url": "https://evil.example/MDSoftware-DE/repo/issues/1"},
        {"case_url": "https://github.com/other/repo/issues/1"},
        {"case_url": "https://github.com/MDSoftware-DE/repo/pull/1"},
    ],
)
def test_tracking_rejects_invalid_payloads(tracking_context, changes):
    payload = _payload()
    payload.update(changes)

    response = tracking_context["client"].patch(
        _url(),
        payload,
        content_type="application/json",
        **tracking_context["headers"],
    )

    assert response.status_code == 400
    assert not CveTracker.objects.exists()
    assert not CveComment.objects.exists()
    assert not CveTrackerEvent.objects.exists()


@pytest.mark.django_db
def test_tracking_rolls_back_when_comment_creation_fails(tracking_context):
    with patch(
        "opencve.api.v2.viewsets.projects.CveComment.objects.create",
        side_effect=RuntimeError("database failure"),
    ):
        with pytest.raises(RuntimeError, match="database failure"):
            tracking_context["client"].patch(
                _url(),
                _payload(),
                content_type="application/json",
                **tracking_context["headers"],
            )

    assert not CveTracker.objects.exists()
    assert not CveComment.objects.exists()
    assert not CveTrackerEvent.objects.exists()


@pytest.mark.django_db
def test_tracking_get_returns_current_state_and_event_history(tracking_context):
    tracking_context["client"].patch(
        _url(),
        _payload(),
        content_type="application/json",
        **tracking_context["headers"],
    )

    response = tracking_context["client"].get(_url(), **tracking_context["headers"])

    assert response.status_code == 200
    assert response.json()["status"] == "analysis_in_progress"
    assert response.json()["events"] == [
        {
            "event_id": "ops-triage:event-1",
            "status": "analysis_in_progress",
            "case_url": CASE_URL,
            "created_at": response.json()["events"][0]["created_at"],
        }
    ]


def test_tracking_comment_renders_case_link_and_escapes_untrusted_html():
    body = f"Authoritative case: {CASE_URL}\n<script>alert(1)</script>"

    rendered = Template("{{ body|urlize|linebreaksbr }}").render(
        Context({"body": body})
    )

    assert f'href="{CASE_URL}"' in rendered
    assert "<script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
