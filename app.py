import os

from flask import Flask, jsonify, render_template, request

from reporting import compact_products
from service import ResearchInputError, research_report


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/research")
    def api_research():
        payload = request.get_json(silent=True) or {}
        query = payload.get("query", "")
        if not isinstance(query, str):
            return jsonify({"error": "Query must be a string."}), 400

        try:
            report, _ = research_report(query)
            data = report.model_dump(mode="json")
            data["affected_products"] = [
                item.model_dump(mode="json") for item in compact_products(report.affected_products)
            ]
            return jsonify({"report": data})
        except ResearchInputError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            app.logger.exception("Research request failed")
            return jsonify({"error": "Research could not be completed. Please try again."}), 502

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "NVD-XRAY"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )
