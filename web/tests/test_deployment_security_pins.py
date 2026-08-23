from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class DeploymentSecurityPinTests(unittest.TestCase):
    def test_compose_uses_fixed_database_and_cache_versions(self):
        compose = (REPOSITORY_ROOT / "docker" / "docker-compose.yaml").read_text()

        self.assertIn("image: redis:8.8.1-alpine", compose)
        self.assertIn("image: postgres:${POSTGRES_VERSION:-15.19}", compose)
        self.assertNotIn(":latest", compose)

    def test_example_environment_matches_postgres_fixed_floor(self):
        example = (REPOSITORY_ROOT / "docker" / "conf" / ".env.example").read_text()

        self.assertIn("POSTGRES_VERSION=15.19", example)


if __name__ == "__main__":
    unittest.main()
