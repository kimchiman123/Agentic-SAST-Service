"""
정량 평가 스크립트 (Precision, Recall, F1-Score 계산)

정답지(eval_dataset.json)와 에이전트 탐지 결과를 비교하여
오탐(FP), 미탐(FN), 정탐(TP)을 산출하고 최종 F1-Score를 계산합니다.
"""
import json
import os

DATASET_PATH = os.path.join(os.path.dirname(__file__), "eval_dataset.json")

# 탐지 결과의 type 필드를 정답지의 id와 매칭하기 위한 키워드 맵
# 에이전트가 반환하는 vulnerability_type / title 등에서 핵심 키워드를 추출하여 매핑
KEYWORD_MAP = {
    "VULN-001": ["md5", "해시", "hash", "암호화"],
    "VULN-002": ["eval", "코드 인젝션", "code injection", "rce", "임의 코드"],
    "VULN-003": ["idor", "접근 통제", "access control", "권한", "소유권"],
    "VULN-004": ["음수", "negative", "로직", "logic", "bypass", "우회"],
    "VULN-005": ["하드코딩", "hardcoded", "credential", "자격증명", "admin"],
    "VULN-006": ["토큰", "token", "jwt", "세션", "인증 토큰"],
    "VULN-007": ["에러", "오류 처리", "error", "정보 노출", "스택"],
    "VULN-008": ["열거", "enumeration", "타이밍", "timing", "사용자 열거"],
    "VULN-009": ["경쟁 조건", "race condition", "동시성", "toctou", "원자적"],
    "VULN-010": ["타입 검증", "type", "유효성", "validation", "프로토타입"],
    "VULN-011": ["상태 기반", "권한 우회", "session", "broken access", "타인"]
}


def load_ground_truth(dataset_path=DATASET_PATH):
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    all_vulns = []
    for item in data:
        file_path = item.get("file_path", "")
        for v in item.get("vulnerabilities", []):
            v["file_path"] = file_path
            all_vulns.append(v)
    return all_vulns


def match_detection(detected_item, ground_truth_vulns):
    """
    탐지 결과 항목 하나를 정답지와 매칭합니다.
    
    매칭 우선순위:
    1. 라인 번호가 정답지의 lines와 겹치는 경우
    2. type/title/description 텍스트에 키워드가 포함된 경우
    """
    det_text = " ".join([
        str(detected_item.get("type", "")),
        str(detected_item.get("title", "")),
        str(detected_item.get("description", "")),
        str(detected_item.get("vulnerability_type", ""))
    ]).lower()
    
    det_lines = set(detected_item.get("lines", []))
    
    best_match = None
    best_score = 0
    
    for gt in ground_truth_vulns:
        # 파일명이 다르면 패스 (오매칭 방지)
        gt_file = gt.get("file_path", "").split("/")[-1]
        det_file = detected_item.get("file_name", "")
        if det_file and gt_file and det_file != gt_file:
            continue
            
        score = 0
        gt_lines = set(gt.get("lines", []))
        
        # 라인 번호 매칭 (가중치 높음)
        line_overlap = len(det_lines & gt_lines)
        if line_overlap > 0:
            score += line_overlap * 5
        
        # 키워드 매칭
        keywords = KEYWORD_MAP.get(gt["id"], [])
        keyword_hits = sum(1 for kw in keywords if kw.lower() in det_text)
        score += keyword_hits * 2
        
        if score > best_score:
            best_score = score
            best_match = gt
    
    # 최소 점수 임계값 (키워드 1개 이상 또는 라인 1개 이상 매칭)
    if best_score >= 2:
        return best_match
    return None


def calculate_metrics(detected_results, dataset_path=DATASET_PATH):
    ground_truth = load_ground_truth(dataset_path)
    total_gt = len(ground_truth)
    
    matched_gt_ids = set()
    true_positives = 0
    false_positives = 0
    match_details = []
    
    for det in detected_results:
        matched = match_detection(det, ground_truth)
        if matched and matched["id"] not in matched_gt_ids:
            true_positives += 1
            matched_gt_ids.add(matched["id"])
            match_details.append({
                "탐지": det.get("type", det.get("title", "알 수 없음")),
                "매칭된 정답": f'{matched["id"]} ({matched["type"]})',
                "결과": "정탐 (TP)"
            })
        elif matched and matched["id"] in matched_gt_ids:
            # 이미 매칭된 정답에 중복 탐지 -> 별도 카운트하지 않음
            match_details.append({
                "탐지": det.get("type", det.get("title", "알 수 없음")),
                "매칭된 정답": f'{matched["id"]} (중복)',
                "결과": "중복 탐지"
            })
        else:
            false_positives += 1
            match_details.append({
                "탐지": det.get("type", det.get("title", "알 수 없음")),
                "매칭된 정답": "-",
                "결과": "오탐 (FP)"
            })
    
    false_negatives = total_gt - true_positives
    missed_vulns = [gt for gt in ground_truth if gt["id"] not in matched_gt_ids]
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / total_gt if total_gt > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "summary": {
            "정답지 총 취약점 수": total_gt,
            "정탐 (True Positives)": true_positives,
            "오탐 (False Positives)": false_positives,
            "미탐 (False Negatives)": false_negatives,
            "정밀도 (Precision)": round(precision, 4),
            "재현율 (Recall)": round(recall, 4),
            "F1-Score": round(f1, 4)
        },
        "severity_breakdown": _severity_breakdown(ground_truth, matched_gt_ids),
        "match_details": match_details,
        "missed_vulnerabilities": [
            {"id": v["id"], "type": v["type"], "severity": v["severity"]}
            for v in missed_vulns
        ]
    }


def _severity_breakdown(ground_truth, matched_ids):
    """심각도별 탐지율 산출"""
    severity_groups = {}
    for gt in ground_truth:
        sev = gt["severity"]
        if sev not in severity_groups:
            severity_groups[sev] = {"total": 0, "detected": 0}
        severity_groups[sev]["total"] += 1
        if gt["id"] in matched_ids:
            severity_groups[sev]["detected"] += 1
    
    result = {}
    for sev, counts in severity_groups.items():
        rate = counts["detected"] / counts["total"] if counts["total"] > 0 else 0
        result[sev] = {
            "총 개수": counts["total"],
            "탐지 수": counts["detected"],
            "탐지율": f"{round(rate * 100, 1)}%"
        }
    return result


def print_report(metrics):
    print("\n" + "=" * 60)
    print("       정량 평가 결과 (Quantitative Evaluation)")
    print("=" * 60)
    
    print("\n[요약]")
    for k, v in metrics["summary"].items():
        print(f"  {k}: {v}")
    
    print("\n[심각도별 탐지율]")
    for sev, info in metrics["severity_breakdown"].items():
        print(f"  {sev}: {info['탐지 수']}/{info['총 개수']} ({info['탐지율']})")
    
    print("\n[매칭 상세]")
    for d in metrics["match_details"]:
        print(f"  [{d['결과']}] {d['탐지']} -> {d['매칭된 정답']}")
    
    if metrics["missed_vulnerabilities"]:
        print("\n[미탐 취약점 목록]")
        for v in metrics["missed_vulnerabilities"]:
            print(f"  - {v['id']} | {v['severity']} | {v['type']}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    # 테스트용 가상 탐지 결과 (실제 실행 시 eval_method_a/b에서 제공)
    sample_detected = [
        {"type": "취약한 해시 알고리즘 사용", "lines": [19, 20]},
        {"type": "코드 인젝션", "lines": [35, 36]},
        {"type": "접근 통제 누락", "lines": [48, 69]},
        {"type": "비즈니스 로직 결함", "lines": [64, 70]}
    ]
    
    metrics = calculate_metrics(sample_detected)
    print_report(metrics)
