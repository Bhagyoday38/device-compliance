import os
import tempfile
import unittest
from io import BytesIO

from openpyxl import load_workbook
from werkzeug.datastructures import MultiDict

from app import create_app
from app.routes import JOBS


class AppWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app()
        self.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret",
            UPLOAD_FOLDER=os.path.join(self.temp_dir.name, "uploads"),
            OUTPUT_FOLDER=os.path.join(self.temp_dir.name, "output"),
        )
        os.makedirs(self.app.config["UPLOAD_FOLDER"])
        os.makedirs(self.app.config["OUTPUT_FOLDER"])
        JOBS.clear()
        self.client = self.app.test_client()

    def tearDown(self):
        JOBS.clear()
        self.temp_dir.cleanup()

    def test_home_page_displays_upload_form(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Drop your files here", response.data)

    def test_upload_without_supported_files_returns_to_home(self):
        response = self.client.post(
            "/upload",
            data={"files": (BytesIO(b"not a spreadsheet"), "notes.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No supported CSV/XLSX files were uploaded.", response.data)
        self.assertEqual(JOBS, {})

    def test_upload_process_and_download_workflow(self):
        files = MultiDict([
            (
                "files",
                (
                    BytesIO(
                        b"Computer Name,Serial No,User Name,Full User Name,"
                        b"Entity,Last Report Time\n"
                        b"HOST-001.example.com,SERIAL-001,EXAMPLE\\jdoe,"
                        b"Jane Doe,NCL,2025-01-01\n"
                    ),
                    "bigfix_export.csv",
                ),
            ),
            (
                "files",
                (
                    BytesIO(
                        b"deviceName,serialNumber,osVersion,lastSyncDateTime,"
                        b"userPrincipalName\n"
                        b"host-001,SERIAL-001,4.10,2025-01-02,jdoe@example.com\n"
                    ),
                    "intune_export.csv",
                ),
            ),
        ])

        review = self.client.post(
            "/upload",
            data=files,
            content_type="multipart/form-data",
        )

        self.assertEqual(review.status_code, 200)
        self.assertIn(b"Review source mapping", review.data)
        job = next(iter(JOBS.values()))
        self.assertEqual(
            {item["detected_source"] for item in job["files"]},
            {"bigfix", "intune"},
        )
        intune_file = next(
            item for item in job["files"]
            if item["detected_source"] == "intune"
        )
        self.assertEqual(intune_file["versions"], ["4.10"])

        form_data = {
            f"source_{item['id']}": item["detected_source"]
            for item in job["files"]
        }
        form_data["minimum_version_intune"] = "4.10"
        dashboard = self.client.post(
            f"/process/{job['id']}",
            data=form_data,
        )

        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Compliance dashboard", dashboard.data)
        self.assertEqual(job["summary"]["total"], 1)
        self.assertEqual(job["summary"]["version_failures"]["intune"], 0)
        self.assertEqual(job["summary"]["missing"]["intune"], 0)

        download = self.client.get(f"/download/{job['id']}")

        self.assertEqual(download.status_code, 200)
        self.assertEqual(
            download.mimetype,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        workbook = load_workbook(BytesIO(download.data), read_only=True)
        self.assertEqual(
            workbook.sheetnames,
            ["Bigfix", "Intune", "Edr", "Av", "Dlp", "Cmdb", "Zscaler"],
        )
        sheet = workbook["Bigfix"]
        headers = [cell.value for cell in sheet[1]]
        row = [cell.value for cell in sheet[2]]
        self.assertEqual(row[headers.index("Computer Name")], "HOST-001")
        self.assertEqual(row[headers.index("Serial No")], "SERIAL-001")
        self.assertEqual(row[headers.index("Intune Status")], "Reported")
        workbook.close()
        download.close()

    def test_processing_rejects_minimum_version_not_in_uploaded_data(self):
        upload = self.client.post(
            "/upload",
            data={
                "files": (
                    BytesIO(
                        b"deviceName,serialNumber,osVersion\n"
                        b"HOST-001,SERIAL-001,4.10\n"
                    ),
                    "intune_export.csv",
                )
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 200)
        job = next(iter(JOBS.values()))
        item = job["files"][0]

        response = self.client.post(
            f"/process/{job['id']}",
            data={
                f"source_{item['id']}": "intune",
                "minimum_version_intune": "99.0",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(job["minimum_versions"], {})

    def test_unknown_job_cannot_be_processed_or_downloaded(self):
        process_response = self.client.post("/process/not-a-job")
        download_response = self.client.get("/download/not-a-job")

        self.assertEqual(process_response.status_code, 302)
        self.assertEqual(download_response.status_code, 302)


if __name__ == "__main__":
    unittest.main()