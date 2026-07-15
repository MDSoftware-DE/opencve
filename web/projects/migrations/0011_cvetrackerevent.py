# Generated for the SecOps CVE tracking writeback.

import uuid

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("cves", "0005_add_weakness_upsert_procedure"),
        ("projects", "0010_fix_migrated_report_automation_configuration"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="CveTrackerEvent",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(
                        db_index=True,
                        default=django.utils.timezone.now,
                    ),
                ),
                (
                    "updated_at",
                    models.DateTimeField(
                        db_index=True,
                        default=django.utils.timezone.now,
                    ),
                ),
                ("event_id", models.CharField(max_length=128)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("to_evaluate", "To evaluate"),
                            ("pending_review", "Pending review"),
                            ("analysis_in_progress", "Analysis in progress"),
                            (
                                "remediation_in_progress",
                                "Remediation in progress",
                            ),
                            ("evaluated", "Evaluated"),
                            ("resolved", "Resolved"),
                            ("not_applicable", "Not applicable"),
                            ("risk_accepted", "Risk accepted"),
                        ],
                        max_length=32,
                    ),
                ),
                ("case_url", models.URLField(max_length=500)),
                ("payload_hash", models.CharField(max_length=64)),
                (
                    "author",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="cve_tracking_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "comment",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="tracking_events",
                        to="projects.cvecomment",
                    ),
                ),
                (
                    "cve",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="tracking_events",
                        to="cves.cve",
                    ),
                ),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cve_tracking_events",
                        to="projects.project",
                    ),
                ),
            ],
            options={
                "db_table": "opencve_cve_tracker_events",
                "indexes": [
                    models.Index(
                        fields=["project", "cve", "created_at"],
                        name="idx_cveevt_proj_created",
                    ),
                    models.Index(
                        fields=["event_id"],
                        name="idx_cveevt_event_id",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("project", "cve", "event_id"),
                        name="ix_unique_project_cve_event",
                    ),
                ],
            },
        ),
    ]
