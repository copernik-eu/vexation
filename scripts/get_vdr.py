# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https:#apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import sys
from datetime import datetime
from decimal import Decimal

from cyclonedx.model import XsUri, InvalidUriException
from cyclonedx.model.bom import Bom
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilityRating, VulnerabilityScoreSource, \
    VulnerabilitySeverity, VulnerabilitySource
from cyclonedx.output.xml import Xml, XmlV1Dot6
from nvd_client import NvdApi
from typing import Dict, List, Optional


def main(cve_list: List[str]) -> int:
    client: NvdApi = NvdApi(os.environ.get("API_KEY"))
    vulnerabilities: List[Vulnerability] = [parse_nvd_vulnerability(vulnerability)
                                            for cve_id in cve_list
                                            for vulnerability in client.get_cve_by_id(cve_id)["vulnerabilities"]]
    bom: Bom = Bom(vulnerabilities=vulnerabilities)
    xml_formatter: Xml = XmlV1Dot6(bom)
    print(xml_formatter.output_as_string(indent=2))
    return 0


def parse_nvd_vulnerability(vulnerability: Dict) -> Vulnerability:
    cve: Dict = vulnerability["cve"]
    v_id: str = cve["id"]
    v_published: datetime = datetime.fromisoformat(cve["published"])
    v_last_modified: datetime = datetime.fromisoformat(cve["lastModified"])
    v_desc: Optional[str] = next((desc["value"] for desc in cve["descriptions"] if desc["lang"] == "en"), None)
    v_metrics: Optional[Dict] = cve.get("metrics")
    v_ratings: List[VulnerabilityRating] = [] if v_metrics is None else parse_nvd_metrics(v_metrics)
    v_weaknesses: Optional[List[Dict]] = cve.get("weaknesses")
    cwes: List[int] = [] if v_weaknesses is None else [cwe for weakness in v_weaknesses
                                                       for cwe in __parse_weakness(weakness)]
    return Vulnerability(id=v_id, published=v_published, updated=v_last_modified, description=v_desc, ratings=v_ratings,
                         cwes=cwes)


def parse_nvd_metrics(metrics: Dict) -> List[VulnerabilityRating]:
    result: List[VulnerabilityRating] = []
    cvss2: Optional[List[Dict]] = metrics.get("cvssMetricV2")
    if cvss2 is not None:
        result.extend(parse_cvss2_metric(metric) for metric in cvss2)
    cvss31: Optional[List[Dict]] = metrics.get("cvssMetricV31")
    if cvss31 is not None:
        result.extend(parse_cvss31_metric(metric) for metric in cvss31)
    return result


def parse_cvss2_metric(metric: Dict) -> VulnerabilityRating:
    result: VulnerabilityRating = parse_commons_cvss_metric(metric, VulnerabilityScoreSource.CVSS_V2)
    base_severity: Optional[str] = metric.get("baseSeverity")
    result.severity = None if base_severity is None else VulnerabilitySeverity[base_severity.upper()]
    return result


def parse_cvss31_metric(metric: Dict) -> VulnerabilityRating:
    result: VulnerabilityRating = parse_commons_cvss_metric(metric, VulnerabilityScoreSource.CVSS_V3_1)
    base_severity: Optional[str] = metric["cvssData"].get("baseSeverity")
    result.severity = None if base_severity is None else VulnerabilitySeverity[base_severity.upper()]
    return result


def parse_commons_cvss_metric(metric: Dict, method: VulnerabilityScoreSource) -> VulnerabilityRating:
    source: VulnerabilitySource = __parse_vulnerability_source(metric["source"])
    data: Dict = metric["cvssData"]
    score: Decimal = Decimal(data["baseScore"])
    vector: str = data["vectorString"]
    return VulnerabilityRating(method=method, source=source, score=score, vector=vector)


def __parse_vulnerability_source(source: str) -> VulnerabilitySource:
    url: Optional[XsUri]
    try:
        url = XsUri("mailto:" + source)
    except InvalidUriException:
        try:
            url = XsUri(source)
        except InvalidUriException:
            url = None
    return VulnerabilitySource(url=url)


def __parse_weakness(weakness: Dict) -> List[int]:
    description: Optional[str] = next((desc["value"] for desc in weakness["description"] if desc["lang"] == "en"), None)
    if description is not None and description.startswith("CWE-"):
        try:
            return [int(description[len("CWE-"):])]
        except ValueError:
            pass
    return []


if __name__ == '__main__':
    n: int = len(sys.argv)
    sys.exit(main(sys.argv[1:n]))
