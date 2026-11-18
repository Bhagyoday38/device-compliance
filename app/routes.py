import os

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for
)

from .services.processor import (
    SOURCE_TYPES,
    build_chart_data,
    build_version_catalog,
    export_excel,
    inspect_files,
    process_data,
    save_uploaded_files,
)

main = Blueprint("main", __name__)

# Development storage. For production, move job state to SQLite/PostgreSQL.
JOBS = {}


@main.route("/")
def index():
    return render_template("index.html")


@main.route("/upload", methods=["POST"])
def upload():
    files = [
        file
        for file in request.files.getlist("files")
        if file and file.filename
    ]

    if not files:
        flash(
            "Please select at least one CSV or XLSX file.",
            "error"
        )
        return redirect(url_for("main.index"))

    job_id, saved_files = save_uploaded_files(
        files,
        current_app.config["UPLOAD_FOLDER"]
    )

    if not saved_files:
        flash(
            "No supported CSV/XLSX files were uploaded.",
            "error"
        )
        return redirect(url_for("main.index"))

    inspected = inspect_files(saved_files)

    JOBS[job_id] = {
        "id": job_id,
        "files": inspected,
        "version_catalog": build_version_catalog(inspected),
        "processed": False,
    }

    return render_template(
        "review.html",
        job=JOBS[job_id],
        source_types=SOURCE_TYPES
    )


@main.route("/process/<job_id>", methods=["POST"])
def process(job_id):
    job = JOBS.get(job_id)

    if not job:
        flash("Processing session was not found.", "error")
        return redirect(url_for("main.index"))

    assignments = {}

    for item in job["files"]:
        assignments[item["id"]] = request.form.get(
            f"source_{item['id']}",
            item["detected_source"]
        )

    # Important: after a user changes a file from e.g. EXTRA -> AV,
    # version discovery is performed again using the selected source.
    version_catalog = build_version_catalog(
        job["files"],
        assignments
    )

    minimum_versions = {}

    for source in SOURCE_TYPES:
        selected = request.form.get(
            f"minimum_version_{source}",
            ""
        ).strip()

        if selected:
            # Prevent selecting a value that did not actually exist
            # in the files assigned to this application.
            if selected in version_catalog.get(source, []):
                minimum_versions[source] = selected

    outputs, summary = process_data(
        job["files"],
        assignments,
        minimum_versions
    )

    output_dir = os.path.join(
        current_app.config["OUTPUT_FOLDER"],
        job_id
    )
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(
        output_dir,
        "Consolidated_Device_Report.xlsx"
    )

    export_excel(outputs, output_path)

    job.update({
        "assignments": assignments,
        "version_catalog": version_catalog,
        "minimum_versions": minimum_versions,
        "summary": summary,
        "chart_data": build_chart_data(summary),
        "output_path": output_path,
        "processed": True,
    })

    return render_template(
        "dashboard.html",
        job=job
    )


@main.route("/download/<job_id>")
def download(job_id):
    job = JOBS.get(job_id)

    if not job or not job.get("processed"):
        flash("Report is not ready.", "error")
        return redirect(url_for("main.index"))

    if not os.path.exists(job["output_path"]):
        flash(
            "Generated report could not be found.",
            "error"
        )
        return redirect(url_for("main.index"))

    return send_file(
        job["output_path"],
        as_attachment=True,
        download_name="Consolidated_Device_Report.xlsx"
    )
