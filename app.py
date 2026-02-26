from flask import Flask, jsonify
from flask_cors import CORS

from config import config
from routes.analyze import analyze_bp
from utils.logger import setup_logger


logger = setup_logger("phish_guard")


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

    app.register_blueprint(analyze_bp)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app


if __name__ == "__main__":
    flask_app = create_app()
    logger.info("starting app on %s:%s", config.HOST, config.PORT)
    flask_app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
