import hashlib
import json

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from cves.models import Cve
from cves.serializers import CveListSerializer
from organizations.models import Organization
from projects.models import CveComment, CveTracker, CveTrackerEvent, Project
from projects.serializers import (
    ProjectCveTrackingSerializer,
    ProjectDetailSerializer,
    ProjectSerializer,
)


def tracking_payload_hash(payload):
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ProjectViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProjectSerializer
    lookup_field = "name"
    lookup_url_kwarg = "name"

    serializer_classes = {
        "list": ProjectSerializer,
        "retrieve": ProjectDetailSerializer,
    }

    def get_queryset(self):
        if hasattr(self.request, "authenticated_organization"):
            organization = get_object_or_404(
                Organization,
                id=self.request.authenticated_organization.id,
                name=self.kwargs["organization_name"],
            )
        else:
            organization = get_object_or_404(
                Organization,
                members=self.request.user,
                name=self.kwargs["organization_name"],
            )
        return Project.objects.filter(organization=organization).order_by("name").all()

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)


class ProjectCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    lookup_field = "cve_id"

    def _get_organization(self):
        if hasattr(self, "_organization"):
            return self._organization

        if hasattr(self.request, "authenticated_organization"):
            organization = get_object_or_404(
                Organization,
                id=self.request.authenticated_organization.id,
                name=self.kwargs["organization_name"],
            )
        else:
            organization = get_object_or_404(
                Organization,
                members=self.request.user,
                name=self.kwargs["organization_name"],
            )
        self._organization = organization
        return organization

    def _get_project(self):
        if hasattr(self, "_project"):
            return self._project

        self._project = get_object_or_404(
            Project,
            organization=self._get_organization(),
            name=self.kwargs["project_name"],
        )
        return self._project

    def get_queryset(self):
        project = self._get_project()
        vendors = project.subscriptions["vendors"] + project.subscriptions["products"]
        if not vendors:
            return Cve.objects.none()
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__has_any_keys=vendors)
            .all()
        )

    @action(detail=True, methods=["get", "patch"])
    def tracking(self, request, **kwargs):
        cve = self.get_object()
        project = self._get_project()

        if request.method == "GET":
            tracker = CveTracker.objects.filter(project=project, cve=cve).first()
            latest_event = (
                CveTrackerEvent.objects.filter(project=project, cve=cve)
                .order_by("-created_at", "-id")
                .first()
            )
            return Response(
                {
                    "cve_id": cve.cve_id,
                    "status": tracker.status if tracker else None,
                    "case_url": latest_event.case_url if latest_event else None,
                    "event_id": latest_event.event_id if latest_event else None,
                }
            )

        api_token = getattr(request, "api_token", None)
        if api_token is None:
            raise PermissionDenied("An organization API token is required.")
        author = api_token.created_by
        if author is None:
            raise PermissionDenied("The organization API token has no audit author.")

        serializer = ProjectCveTrackingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = dict(serializer.validated_data)
        payload_hash = tracking_payload_hash(payload)

        with transaction.atomic():
            Project.objects.select_for_update().get(pk=project.pk)
            tracker = (
                CveTracker.objects.select_for_update()
                .filter(project=project, cve=cve)
                .first()
            )
            existing_event = CveTrackerEvent.objects.filter(
                project=project,
                cve=cve,
                event_id=payload["event_id"],
            ).first()

            if existing_event:
                if existing_event.payload_hash != payload_hash:
                    return Response(
                        {"detail": "The event ID already has a different payload."},
                        status=status.HTTP_409_CONFLICT,
                    )
                return Response(
                    {
                        "cve_id": cve.cve_id,
                        "status": existing_event.status,
                        "case_url": existing_event.case_url,
                        "event_id": existing_event.event_id,
                        "created": False,
                    }
                )

            if tracker is None:
                tracker = CveTracker(project=project, cve=cve)
            tracker.status = payload["status"]
            tracker.save()

            comment = CveComment.objects.create(
                project=project,
                cve=cve,
                author=author,
                body=payload["comment"],
            )
            event = CveTrackerEvent.objects.create(
                project=project,
                cve=cve,
                author=author,
                comment=comment,
                event_id=payload["event_id"],
                status=payload["status"],
                case_url=payload["case_url"],
                payload_hash=payload_hash,
            )

        return Response(
            {
                "cve_id": cve.cve_id,
                "status": event.status,
                "case_url": event.case_url,
                "event_id": event.event_id,
                "created": True,
            }
        )
