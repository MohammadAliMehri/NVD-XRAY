import os

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
and source references, then return the required structured schema. Do not populate
public_poc_count, public_pocs, or poc_index_url; those fields are enriched separately
from PoCIndex metadata after report validation.
The remediation, security_recommendations, and limitations fields must be JSON arrays
of strings, never JSON encoded as a single string. For keyword searches, populate
search_results with the bounded returned matches.
"""


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def create_research_agent():
    load_dotenv()
    model = ChatOpenAI(
        model=_required_env("NVIDIA_MODEL"),
        api_key=_required_env("NVIDIA_API_KEY"),
        base_url=os.getenv("NVIDIA_BASE_URL",
                           "https://integrate.api.nvidia.com/v1"),
        temperature=0,
        timeout=float(os.getenv("NVIDIA_TIMEOUT_SECONDS", "60")),
        max_retries=1,
    )
    return create_agent(
        model=model,
        tools=[get_cve_details, search_cves],
        system_prompt=SYSTEM_PROMPT,
        response_format=ToolStrategy(schema=VulnerabilityReport),
    )


def research(query: str) -> dict:
    agent = create_research_agent()
    return agent.invoke({"messages": [{"role": "user", "content": query}]})
