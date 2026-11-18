import os
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024
    app.config["UPLOAD_FOLDER"] = os.path.abspath(
        os.path.join(app.root_path, "..", "uploads")
    )
    app.config["OUTPUT_FOLDER"] = os.path.abspath(
        os.path.join(app.root_path, "..", "output")
    )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["OUTPUT_FOLDER"], exist_ok=True)

    from .routes import main
    app.register_blueprint(main)

    return app
