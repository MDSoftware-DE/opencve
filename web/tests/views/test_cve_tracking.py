import pytest
from bs4 import BeautifulSoup
from django.template.loader import render_to_string
from django.test import RequestFactory

from cves.models import Cve
from projects.models import CveComment


CASE_URL = "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42"


@pytest.mark.django_db
def test_tracking_comment_renders_one_safe_clickable_case_link(
    create_organization,
    create_project,
    create_user,
):
    user = create_user(username="secops")
    organization = create_organization(name="md-software", user=user)
    project = create_project(
        name="colossus",
        organization=organization,
        vendors=["siemens"],
    )
    cve = Cve.objects.create(
        cve_id="CVE-2026-1234",
        title="Tracking link test",
        description="Tracking link test",
        vendors=["siemens"],
        weaknesses=[],
        metrics={},
    )
    comment = CveComment.objects.create(
        project=project,
        cve=cve,
        author=user,
        body=(
            f"SecOps case resolved: {CASE_URL}\n"
            "<script>alert(1)</script>\n"
            "javascript:alert(2)\n"
            "<img src=x onerror=alert(3)>"
        ),
    )
    request = RequestFactory().get("/")
    request.user = user
    request.current_organization = organization

    html = render_to_string(
        "cves/includes/tracking.html",
        {
            "cve": cve,
            "filtered_projects": [
                {
                    "project": project,
                    "tracker": None,
                    "comments": [{"comment": comment, "replies": []}],
                    "comment_count": 1,
                }
            ],
            "user": user,
        },
        request=request,
    )
    soup = BeautifulSoup(html, "html.parser")
    links = soup.select(".project-comment-body a")

    assert len(links) == 1
    assert links[0].get("href") == CASE_URL
    assert links[0].get_text() == CASE_URL
    assert "nofollow" in links[0].get("rel", [])
    assert soup.find("script") is None
    assert not any(
        link.get("href", "").lower().startswith("javascript:")
        for link in soup.find_all("a")
    )
    assert all("onerror" not in tag.attrs for tag in soup.find_all(True))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(3)&gt;" in html
