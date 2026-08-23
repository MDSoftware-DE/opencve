from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TEST_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "tests.yml"
RELEASE_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release-image.yml"


class DeploymentSecurityPinTests(unittest.TestCase):
    def test_compose_uses_fixed_database_and_cache_versions(self):
        compose = (REPOSITORY_ROOT / "docker" / "docker-compose.yaml").read_text()

        self.assertIn("image: redis:8.8.1-alpine", compose)
        self.assertIn("image: postgres:${POSTGRES_VERSION:-15.19}", compose)
        self.assertNotIn(":latest", compose)

    def test_example_environment_matches_postgres_fixed_floor(self):
        example = (REPOSITORY_ROOT / "docker" / "conf" / ".env.example").read_text()

        self.assertIn("POSTGRES_VERSION=15.19", example)

    def test_ci_services_match_production_security_pins(self):
        workflow = TEST_WORKFLOW.read_text()

        self.assertEqual(workflow.count("image: postgres:15.19-alpine"), 2)
        self.assertEqual(workflow.count("image: redis:8.8.1-alpine"), 1)
        self.assertNotIn("image: redis/redis-stack", workflow)
        release_workflow = RELEASE_WORKFLOW.read_text()
        self.assertIn("image: postgres:15.19-alpine", release_workflow)


if __name__ == "__main__":
    unittest.main()
