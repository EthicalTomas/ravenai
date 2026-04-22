from __future__ import annotations

import unittest
from data.models import Endpoint, Vulnerability
from reports.repro_steps import ReproductionStepGenerator

class TestReproSteps(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoint = Endpoint(url="https://example.com/api", method="POST")
        self.generator = ReproductionStepGenerator()

    def test_xss_steps(self) -> None:
        vuln = Vulnerability(
            vuln_type="reflected_xss",
            endpoint=self.endpoint,
            severity="high",
            confidence=0.9,
            payloads=["<script>alert(1)</script>"],
            evidence=["<script>alert(1)</script>"]
        )
        steps = self.generator.generate_steps(vuln)
        self.assertEqual(len(steps), 4)
        self.assertIn("XSS payload", steps[1])
        self.assertIn("<script>alert(1)</script>", steps[1])
        self.assertIn("evidence: <script>alert(1)</script>", steps[3])

    def test_sqli_steps(self) -> None:
        vuln = Vulnerability(
            vuln_type="sqli",
            endpoint=self.endpoint,
            severity="critical",
            confidence=0.95,
            payloads=["' OR 1=1--"],
            evidence=["SQL syntax error"]
        )
        steps = self.generator.generate_steps(vuln)
        self.assertIn("SQL injection payload", steps[1])
        self.assertIn("' OR 1=1--", steps[1])

    def test_idor_steps(self) -> None:
        vuln = Vulnerability(
            vuln_type="idor",
            endpoint=self.endpoint,
            severity="high",
            confidence=0.8,
            payloads=["1337"],
            evidence=["private_data_of_another_user"]
        )
        steps = self.generator.generate_steps(vuln)
        self.assertIn("Modify the resource identifier", steps[1])
        self.assertIn("1337", steps[1])

    def test_generic_steps(self) -> None:
        vuln = Vulnerability(
            vuln_type="unknown_vuln",
            endpoint=self.endpoint,
            severity="medium",
            confidence=0.5,
            payloads=["generic_payload"],
            evidence=["generic_evidence"]
        )
        steps = self.generator.generate_steps(vuln)
        self.assertIn("generic_payload", steps[1])
        self.assertIn("generic_evidence", steps[3])

    def test_report_builder_integration(self) -> None:
        from reports.report_builder import ReportBuilder
        from pathlib import Path
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            template_path = Path(tmp_dir) / "generic.md"
            template_path.write_text("# {title}\n## Reproduction Steps\n{reproduction_steps}\n", encoding="utf-8")
            
            builder = ReportBuilder(templates_dir=Path(tmp_dir))
            vuln = Vulnerability(
                vuln_type="generic",
                endpoint=self.endpoint,
                severity="low",
                confidence=0.1,
                payloads=["p1"],
                evidence=["e1"]
            )
            reports = builder.build([vuln])
            self.assertEqual(len(reports), 1)
            report = reports[0]
            
            # Check sections dictionary
            self.assertIn("reproduction_steps", report.sections.to_dict())
            # Check rendered markdown
            self.assertIn("## Reproduction Steps", report.markdown)
            self.assertIn("1. Send an HTTP POST request to https://example.com/api", report.markdown)

if __name__ == "__main__":
    unittest.main()
