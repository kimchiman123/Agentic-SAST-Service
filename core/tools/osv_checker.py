import os
import json
import urllib.request
from typing import List, Dict, Any

def scan_dependencies(target_dir: str) -> List[Dict[str, Any]]:
    """
    target_dir 내부에 package.json, requirements.txt 등이 있는지 확인 후,
    OSV.dev API를 호출하여 취약점 목록을 획득합니다.
    (현재 npm package.json만 시범 지원 구성)
    """
    package_json_path = os.path.join(target_dir, "package.json")
    if not os.path.exists(package_json_path):
        return []

    try:
        with open(package_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] package.json 파싱 실패: {e}")
        return []

    deps = {}
    if "dependencies" in data:
        deps.update(data["dependencies"])
    if "devDependencies" in data:
        deps.update(data["devDependencies"])

    queries = []
    for pkg, version in deps.items():
        # 시멘틱 버저닝 기호 제거 (^, ~, >= 등)
        clean_version = version.replace('^', '').replace('~', '').replace('>=', '').replace('>', '').replace('=', '').strip()
        queries.append({
            "package": {"name": pkg, "ecosystem": "npm"},
            "version": clean_version
        })

    if not queries:
        return []

    print(f"  [*] OSV API로 {len(queries)}개의 npm 라이브러리 취약점 1차 조회 중...")
    
    req_body = json.dumps({"queries": queries}).encode('utf-8')
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=req_body, headers={'Content-Type': 'application/json'})
    
    results = []
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            
            for i, result in enumerate(res_data.get("results", [])):
                if "vulns" in result:
                    vulns = result["vulns"]
                    pkg_info = queries[i]
                    for v in vulns:
                        # Agent에게 주입할 핵심 정보만 추출
                        results.append({
                            "package": pkg_info["package"]["name"],
                            "version": pkg_info["version"],
                            "cve_id": v.get("id"),
                            "summary": v.get("summary", "알려진 위협 (상세 내용은 OSV 참고)"),
                        })
    except Exception as e:
        print(f"  [!] OSV API 통신 실패: {e}")
        
    return results
