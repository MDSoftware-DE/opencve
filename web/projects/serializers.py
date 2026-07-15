import re
from urllib.parse import urlsplit

from rest_framework import serializers

from cves.constants import PRODUCT_SEPARATOR
from projects.models import CVE_TRACKER_STATUS_CHOICES, Project


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "description",
        ]


class ProjectDetailSerializer(serializers.ModelSerializer):
    subscriptions = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "description",
            "subscriptions",
        ]

    @staticmethod
    def get_subscriptions(instance):
        subscriptions = {"vendors": instance.subscriptions["vendors"], "products": {}}
        for product in instance.subscriptions["products"]:
            v_name, p_name = product.split(PRODUCT_SEPARATOR)
            if v_name not in subscriptions["products"]:
                subscriptions["products"][v_name] = []
            subscriptions["products"][v_name].append(p_name)
        return subscriptions


GITHUB_ISSUE_PATH = re.compile(r"^/MDSoftware-DE/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*/?$")


class ProjectCveTrackingSerializer(serializers.Serializer):
    event_id = serializers.CharField(max_length=128, trim_whitespace=True)
    status = serializers.ChoiceField(choices=CVE_TRACKER_STATUS_CHOICES)
    comment = serializers.CharField(
        max_length=4096,
        allow_blank=False,
        trim_whitespace=True,
    )
    case_url = serializers.URLField(max_length=500)

    def validate_case_url(self, value):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or parsed.query
            or parsed.fragment
            or not GITHUB_ISSUE_PATH.fullmatch(parsed.path)
        ):
            raise serializers.ValidationError(
                "Use an HTTPS github.com/MDSoftware-DE issue URL."
            )
        return value.rstrip("/")
