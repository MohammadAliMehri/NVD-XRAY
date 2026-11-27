import os
import threading
import time
import uuid
from collections import OrderedDict

from flask import Flask, jsonify, render_template, request

from agent import answer_report_question, check_local_model_ready
from reporting import compact_products
from schemas import VulnerabilityReport
from service import ResearchInputError, research_report


REPORT_CACHE_TTL_SECONDS = 7200
REPORT_CACHE_MAX_ITEMS = 100
MAX_CHAT_QUESTION_LENGTH = 1200


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    report_cache: OrderedDict[str, tuple[float,
                                         VulnerabilityReport]] = OrderedDict()
    cache_lock = threading.Lock()

    def cache_report(report: VulnerabilityReport) -> str:
        now = time.time()
        report_id = uuid.uuid4().hex
        with cache_lock:
            for cached_id, (created_at, _) in list(report_cache.items()):
                if now - created_at > REPORT_CACHE_TTL_SECONDS:
                    report_cache.pop(cached_id, None)
            report_cache[report_id] = (now, report)
            while len(report_cache) > REPORT_CACHE_MAX_ITEMS:
                report_cache.popitem(last=False)
        return report_id

    def get_cached_report(report_id: str) -> VulnerabilityReport | None:
        with cache_lock:
            cached = report_cache.get(report_id)
            if not cached:
                return None
            created_at, report = cached
            if time.time() - created_at > REPORT_CACHE_TTL_SECONDS:
                report_cache.pop(report_id, None)
                return None
            report_cache.move_to_end(report_id)
            return report

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
            return jsonify({"report": data, "report_id": cache_report(report)})
        except ResearchInputError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            app.logger.exception("Research request failed")
            return jsonify({"error": "Research could not be completed. Please try again."}), 502

    @app.post("/api/chat")
    def api_chat():
        payload = request.get_json(silent=True) or {}
        report_id = payload.get("report_id", "")
        question = payload.get("question", "")
        if not isinstance(report_id, str) or not report_id:
            return jsonify({"error": "A valid report_id is required."}), 400
        if not isinstance(question, str) or not question.strip():
            return jsonify({"error": "Enter a question about the current CVE report."}), 400
        question = question.strip()
        if len(question) > MAX_CHAT_QUESTION_LENGTH:
            return jsonify({"error": f"Question is too long; maximum is {MAX_CHAT_QUESTION_LENGTH} characters."}), 400

        report = get_cached_report(report_id)
        if report is None:
            return jsonify({"error": "This report session has expired. Run the research again."}), 404

        try:
            answer = answer_report_question(report, question)
            return jsonify({"answer": answer, "cve_id": report.cve_id})
        except Exception:
            app.logger.exception("Report chat request failed")
            return jsonify({"error": "The local model is unavailable. Check LM Studio and try again."}), 502

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "NVD-XRAY"})

    @app.get("/ready")
    def ready():
        try:
            model_status = check_local_model_ready()
        except Exception:
            app.logger.warning(
                "LM Studio readiness check failed", exc_info=True)
            return jsonify({"status": "not-ready", "model": "unavailable"}), 503
        return jsonify({"status": "ready" if model_status["ready"] else "not-ready", **model_status}), 200 if model_status["ready"] else 503

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )
