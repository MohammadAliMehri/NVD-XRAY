import os

import httpx
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.agents.structured_output import ToolStrategy
from langchain_openai import ChatOpenAI

from schemas import VulnerabilityReport
from tools import get_cve_details, search_cves


SYSTEM_PROMPT = """You are NVD-XRAY, a careful vulnerability research assistant.
Use the NVD tools for CVE facts. Choose get_cve_details for an exact CVE identifier
and search_cves for a product or vulnerability phrase. Limit keyword results.
Never invent scores, affected versions, patches, or references. Distinguish NVD
record facts from general defensive advice. Remediation may only repeat guidance
explicitly present in retrieved references or clearly describe it as model guidance.
If data is absent or uncertain, record it in limitations. If no record is found,
return a report that says so without fabricating a CVE. Summarize the vulnerability,
impact, affected products and versions, remediation, security recommendations,
and source references, then return the required structured schema. Populate impact
and attack_surface as concise evidence-based descriptions and set confidence to
high when the NVD record is complete, otherwise medium or low. Do not populate
public_poc_count, public_pocs, or poc_index_url; those fields are enriched separately
from PoCIndex metadata after report validation.
The remediation, security_recommendations, and limitations fields must be JSON arrays
of strings, never JSON encoded as a single string. For keyword searches, populate
search_results with the bounded returned matches. Never provide exploit code or
step-by-step offensive execution instructions.
"""


def create_chat_model() -> ChatOpenAI:
    load_dotenv()
    return ChatOpenAI(
        model=os.getenv("LLM_MODEL", "spark-x2.6-4b-uncensored"),
        api_key=os.getenv("LLM_API_KEY", "lm-studio"),
        base_url=os.getenv("LLM_BASE_URL", "http://127.0.0.1:1234/v1"),
        temperature=0,
        timeout=float(os.getenv("LLM_TIMEOUT_SECONDS", "120")),
        max_retries=1,
    )


def check_local_model_ready() -> dict[str, object]:
    load_dotenv()
    base_url = os.getenv("LLM_BASE_URL", "http://127.0.0.1:1234/v1").rstrip("/")
    model_name = os.getenv("LLM_MODEL", "spark-x2.6-4b-uncensored")
    response = httpx.get(f"{base_url}/models", timeout=5)
    response.raise_for_status()
    models = {
        str(item.get("id")) for item in response.json().get("data", []) if item.get("id")
    }
    return {
        "ready": model_name in models,
        "model": model_name,
        "available_models": sorted(models),
        "base_url": base_url,
    }


def create_research_agent():
    model = create_chat_model()
    return create_agent(
        model=model,
        tools=[get_cve_details, search_cves],
        system_prompt=SYSTEM_PROMPT,
        response_format=ToolStrategy(schema=VulnerabilityReport),
    )


def research(query: str) -> dict:
    agent = create_research_agent()
    return agent.invoke({"messages": [{"role": "user", "content": query}]})


def answer_report_question(report: VulnerabilityReport, question: str) -> str:
    model = create_chat_model()
    context = report.model_dump_json()
    response = model.invoke(
        [
            {
                "role": "system",
                "content": (
                    "You are the NVD-XRAY report assistant. Answer only from the validated "
                    "report JSON below. Explain NVD facts, impact, affected versions, "
                    "remediation, recommendations, limitations, and public PoC metadata. "
                    "If the report does not contain an answer, say so and recommend the "
                    "listed references. Do not invent facts, claim links are safe, or provide "
                    "exploit code or offensive step-by-step instructions. Be concise."
                ),
            },
            {
                "role": "user",
                "content": f"REPORT JSON:\n{context}\n\nQUESTION:\n{question}",
            },
        ]
    )
    if isinstance(response.content, str):
        return response.content.strip()
    return " ".join(
        str(item.get("text", "")) for item in response.content if isinstance(item, dict)
    ).strip()
