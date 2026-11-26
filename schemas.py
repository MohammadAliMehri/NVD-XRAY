from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class AffectedProduct(BaseModel):
    vendor: str
    product: str
    affected_versions: list[str] = Field(default_factory=list)


class Reference(BaseModel):
    url: HttpUrl
    source: str | None = None
    tags: list[str] = Field(default_factory=list)


class SearchMatch(BaseModel):
    cve_id: str
    summary: str
    severity: str | None = None
    cvss_score: float | None = None


class PublicPoc(BaseModel):
    name: str
    url: HttpUrl
    source: str
    stars: int | None = None
    pushed_at: str | None = None


class VulnerabilityReport(BaseModel):
    cve_id: str | None = None
    summary: str
    severity: str | None = None
    cvss_score: float | None = None
    affected_products: list[AffectedProduct] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    security_recommendations: list[str] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    data_source: Literal["NVD"] = "NVD"
    public_poc_count: int = 0
    public_pocs: list[PublicPoc] = Field(default_factory=list)
    poc_index_url: HttpUrl | None = None
    limitations: list[str] = Field(default_factory=list)
    search_results: list[SearchMatch] = Field(default_factory=list)
