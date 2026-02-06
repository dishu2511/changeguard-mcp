import json
import sys
import os
import hashlib
import time
import re
import boto3
from typing import Optional, List, Dict, Any, Literal, Tuple
from dataclasses import dataclass
from botocore.exceptions import BotoCoreError, ClientError

# Type definitions
ReviewerMode = Literal["principal_engineer", "security_reviewer", "finops_reviewer", "delivery_manager"]
OutputLevel = Literal["auto", "summary", "review", "diagnostic"]
SuggestionBudget = Literal["low", "med", "high"]
LLMProvider = Literal["stub", "bedrock"]

# Constants
ALLOWED_SUGGESTION_CATEGORIES = {
    "security",
    "reliability",
    "delivery",
    "finops",
    "compliance",
    "operations",
    "performance",
}

DEFAULT_CACHE_DIR = "/tmp/pushback_cache"
DEFAULT_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_BEDROCK_REGION = os.getenv("DEFAULT_BEDROCK_REGION", "ap-southeast-2")
DEFAULT_BEDROCK_MODEL_ID = os.getenv("DEFAULT_BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")
DEFAULT_BEDROCK_TEMPERATURE = 0.2
DEFAULT_BEDROCK_MAX_TOKENS = 700

# Pydantic-like validation classes
class SuggestedItem:
    def __init__(self, title: str, why: str, category: str, anchor: Optional[str] = None):
        self.title = title
        self.why = why
        self.category = category.strip().lower()
        self.anchor = anchor
        if self.category not in ALLOWED_SUGGESTION_CATEGORIES:
            raise ValueError(f"Invalid category '{self.category}'. Allowed: {sorted(ALLOWED_SUGGESTION_CATEGORIES)}")
    
    def model_dump(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "why": self.why,
            "category": self.category,
            "anchor": self.anchor
        }

class Suggestions:
    def __init__(self, suggested_risks: List[SuggestedItem] = None, 
                 suggested_missing_questions: List[SuggestedItem] = None,
                 suggested_tests: List[SuggestedItem] = None):
        self.suggested_risks = suggested_risks or []
        self.suggested_missing_questions = suggested_missing_questions or []
        self.suggested_tests = suggested_tests or []
    
    def bounded(self, budget: SuggestionBudget) -> "Suggestions":
        limits = {"low": 2, "med": 4, "high": 6}[budget]
        return Suggestions(
            suggested_risks=self.suggested_risks[:limits],
            suggested_missing_questions=self.suggested_missing_questions[:limits],
            suggested_tests=self.suggested_tests[:limits],
        )
    
    @classmethod
    def model_validate(cls, data: Dict[str, Any]) -> "Suggestions":
        risks = [SuggestedItem(**item) for item in data.get("suggested_risks", [])]
        questions = [SuggestedItem(**item) for item in data.get("suggested_missing_questions", [])]
        tests = [SuggestedItem(**item) for item in data.get("suggested_tests", [])]
        return cls(risks, questions, tests)
    
    def model_dump(self) -> Dict[str, Any]:
        return {
            "suggested_risks": [item.model_dump() for item in self.suggested_risks],
            "suggested_missing_questions": [item.model_dump() for item in self.suggested_missing_questions],
            "suggested_tests": [item.model_dump() for item in self.suggested_tests]
        }

def lambda_handler(event, context):
    """AWS Lambda handler for ChangeGuard review gate"""
    try:
        # Extract request data
        body = event.get('body', '{}')
        if isinstance(body, str):
            body = json.loads(body)
        
        # Call the review gate function
        result = review_gate(
            plan=body.get('plan', ''),
            context=body.get('context'),
            mode=body.get('mode', 'principal_engineer'),
            strict=body.get('strict', True),
            output_level=body.get('output_level', 'auto'),
            enable_llm_suggestions=body.get('enable_llm_suggestions', True),
            bedrock_region=DEFAULT_BEDROCK_REGION,
            bedrock_model_id=DEFAULT_BEDROCK_MODEL_ID
        )
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(result)
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': str(e),
                'message': 'Internal server error'
            })
        }

@dataclass
class Signals:
    env: str
    change_type: str
    touches_auth: bool
    touches_data: bool
    rollout: str

def _contains_any(text: str, needles: List[str]) -> bool:
    t = (text or "").lower()
    return any(n.lower() in t for n in needles)

def _hash_key(parts: List[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()

def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def _cache_path(cache_dir: str, key: str) -> str:
    return os.path.join(cache_dir, f"{key}.json")

def _cache_read(cache_dir: str, key: str, ttl_seconds: int) -> Optional[Dict[str, Any]]:
    path = _cache_path(cache_dir, key)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        ts = payload.get("_cached_at", 0)
        if ttl_seconds > 0 and (time.time() - ts) > ttl_seconds:
            return None
        return payload
    except Exception:
        return None

def _cache_write(cache_dir: str, key: str, data: Dict[str, Any]) -> None:
    _ensure_dir(cache_dir)
    path = _cache_path(cache_dir, key)
    tmp = path + ".tmp"
    data2 = dict(data)
    data2["_cached_at"] = time.time()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data2, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def _dedupe_items(items: List[SuggestedItem]) -> List[SuggestedItem]:
    seen: set[str] = set()
    out: List[SuggestedItem] = []
    for it in items:
        key = (it.title.strip().lower(), it.category.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out

def _strip_blocker_language(text: str) -> str:
    t = text
    t = re.sub(r"\bmust\b", "should", t, flags=re.IGNORECASE)
    t = re.sub(r"\breject\b", "consider rejecting", t, flags=re.IGNORECASE)
    t = re.sub(r"\bblock\b", "treat as a concern", t, flags=re.IGNORECASE)
    return t

def _extract_first_json_object(s: str) -> Optional[Dict[str, Any]]:
    if not s:
        return None
    s = s.strip()
    
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    
    start = s.find("{")
    if start == -1:
        return None
    
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                candidate = s[start : i + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        return obj
                except Exception:
                    return None
    return None

def _mode_overrides(mode: str) -> Dict[str, List[str]]:
    if mode == "security_reviewer":
        return {
            "assumptions": [
                "We are assuming exceptions (if any) are time-bound with compensating controls.",
                "We are assuming identity/access is least-privilege and auditable.",
            ],
            "risks": [
                "Security exception becomes permanent and silently expands blast radius.",
                "Missing audit trail makes incident response and compliance reporting harder.",
            ],
            "required_actions": [
                "If requesting an exception: define owner, expiry date, compensating controls, and approver.",
                "Confirm logging/auditing impact and ensure it remains enabled.",
            ],
        }
    if mode == "finops_reviewer":
        return {
            "assumptions": [
                "We are assuming the savings are real (measurable baseline + measurement plan).",
                "We are assuming cost changes won't shift spend elsewhere (data transfer, ops overhead).",
            ],
            "risks": [
                "Savings are overstated due to missing baselines or one-off effects.",
                "Cost reduced in one area but increased in another (hidden transfer/ops costs).",
            ],
            "required_actions": [
                "Provide baseline cost/usage and measurement period (before/after).",
                "List any cost trade-offs (support effort, performance, transfer).",
            ],
        }
    if mode == "delivery_manager":
        return {
            "assumptions": [
                "We are assuming approvals and dependencies can be met within the planned timeline.",
                "We are assuming stakeholders are aligned on scope and acceptance criteria.",
            ],
            "risks": [
                "Timeline slips due to approvals/dependencies not accounted for.",
                "Scope creep turns a small change into a complex programme.",
            ],
            "required_actions": [
                "Confirm approvals needed and lead time (CAB/security/product).",
                "Lock acceptance criteria and identify a clear go/no-go decision owner.",
            ],
        }
    return {
        "assumptions": [
            "We are assuming operability is planned (monitoring, runbooks, ownership).",
            "We are assuming failure modes are understood (rollback, partial failure, dependency outage).",
        ],
        "risks": [
            "Operational ownership unclear → incidents take longer to resolve.",
            "Rollback not tested → outage recovery becomes unpredictable.",
        ],
        "required_actions": [
            "Define owner/on-call expectations and update runbooks/alerts.",
            "Document rollback steps and perform a rollback rehearsal (at least in lower env).",
        ],
    }

def _pick_tradeoff(mode: str) -> Dict[str, Any]:
    if mode == "security_reviewer":
        return {
            "primary_goal": "Reduce security risk",
            "secondary_goals": ["Maintain delivery speed", "Minimise user friction"],
            "willing_to_sacrifice": "We will accept extra change effort and slower delivery if needed.",
        }
    if mode == "finops_reviewer":
        return {
            "primary_goal": "Reduce cost sustainably",
            "secondary_goals": ["Maintain reliability", "Minimise operational overhead"],
            "willing_to_sacrifice": "We will not take savings that increase outage risk or on-call load.",
        }
    if mode == "delivery_manager":
        return {
            "primary_goal": "Deliver safely on time",
            "secondary_goals": ["Maintain quality", "Keep stakeholders aligned"],
            "willing_to_sacrifice": "We will reduce scope before we reduce safety controls.",
        }
    return {
        "primary_goal": "Increase reliability and operability",
        "secondary_goals": ["Maintain delivery velocity", "Control cost"],
        "willing_to_sacrifice": "We will accept some extra build time to avoid future incidents.",
    }

def _core_assumptions() -> List[str]:
    return [
        "What evidence supports the expected timeline and effort?",
        "What are we assuming about dependencies (systems/teams/vendors)?",
        "What are we assuming about non-functional requirements (availability, latency, security)?",
        "What are we assuming about rollback (time, complexity, feasibility)?",
        "What are we assuming about testing/validation coverage?",
        "What are we assuming about change management (approvals, comms, training)?",
    ]

def _core_risks() -> List[str]:
    return [
        "Hidden coupling / unknown dependencies cause delays or outages.",
        "No clear rollback path increases outage duration and customer impact.",
        "Single chokepoint or scaling bottleneck emerges under load.",
        "Testing gap: happy-path works, edge cases fail in production.",
        "Operational gaps: unclear runbooks, alerting, and ownership.",
    ]

def _core_missing_inputs() -> List[str]:
    return [
        "Goal + measurable success criteria (what does 'done' mean?)",
        "Blast radius + customer/user impact assessment",
        "Rollback plan + estimated rollback time",
        "Test plan (pre + post) and validation owner(s)",
        "Approvals needed (CAB/security/product) + lead time",
        "Monitoring/alerting + runbook updates",
    ]

def _detect_evidence(plan: str, context: Optional[str]) -> Dict[str, bool]:
    text = f"{plan}\n{context or ''}"
    has_metrics = _contains_any(text, ["success", "metric", "slo", "sla", "error budget", "latency", "kpi", "p95", "p99", "error rate", "5xx"])
    has_rollback = _contains_any(text, ["rollback", "roll back", "revert", "backout", "back-out", "switch back"])
    has_test = _contains_any(text, ["test", "validate", "validation", "smoke", "uat", "qa", "post-change", "checklist"])
    has_owner = _contains_any(text, ["owner", "on-call", "oncall", "runbook", "ops", "sre", "support team", "duty"])
    has_approvals = _contains_any(text, ["cab", "change", "approval", "approver", "security sign-off", "sign off", "sign-off", "chg-"])
    has_blast = _contains_any(text, ["blast radius", "impact", "customer", "users affected", "downtime", "canary", "blue/green", "blue-green"])
    return {
        "has_metrics": has_metrics,
        "has_rollback": has_rollback,
        "has_test_plan": has_test,
        "has_owner_ops": has_owner,
        "has_approvals": has_approvals,
        "has_blast_radius": has_blast,
    }

def _score_from_evidence(e: Dict[str, bool]) -> int:
    score = 0
    score += 2 if e["has_metrics"] else 0
    score += 2 if e["has_rollback"] else 0
    score += 2 if e["has_test_plan"] else 0
    score += 2 if e["has_owner_ops"] else 0
    score += 1 if e["has_approvals"] else 0
    score += 1 if e["has_blast_radius"] else 0
    return score

def _blockers_from_evidence(e: Dict[str, bool], mode: str) -> List[str]:
    blockers: List[str] = []
    if not e["has_metrics"]:
        blockers.append("Missing measurable success criteria / metrics.")
    if not e["has_rollback"]:
        blockers.append("Missing rollback/backout plan (with estimated rollback time).")
    if not e["has_test_plan"]:
        blockers.append("Missing test/validation plan (pre and post change) and validation owner.")
    if not e["has_owner_ops"]:
        blockers.append("Missing operational ownership (on-call/ops), runbooks, and monitoring plan.")
    if not e["has_blast_radius"]:
        blockers.append("Missing blast radius / user impact assessment.")
    if mode in ("security_reviewer", "delivery_manager", "principal_engineer") and not e["has_approvals"]:
        blockers.append("Missing approvals/change-management plan (e.g., CAB/security/product sign-off).")
    return blockers

def _missing_inputs_from_evidence(e: Dict[str, bool]) -> List[str]:
    missing: List[str] = []
    if not e.get("has_metrics", False):
        missing.append("Goal + measurable success criteria (what does 'done' mean?)")
    if not e.get("has_blast_radius", False):
        missing.append("Blast radius + customer/user impact assessment")
    if not e.get("has_rollback", False):
        missing.append("Rollback plan + estimated rollback time")
    if not e.get("has_test_plan", False):
        missing.append("Test plan (pre + post) and validation owner(s)")
    if not e.get("has_approvals", False):
        missing.append("Approvals needed (CAB/security/product) + lead time")
    if not e.get("has_owner_ops", False):
        missing.append("Monitoring/alerting + runbook updates")
    return missing

def _actions_from_blockers(blockers: List[str]) -> List[str]:
    actions: List[str] = []
    for b in blockers:
        bl = b.lower()
        if "success criteria" in bl or "metrics" in bl:
            actions.append("Define success criteria/metrics and how they will be measured (before/after).")
        elif "rollback" in bl:
            actions.append("Write rollback/backout steps and estimate rollback time; confirm feasibility.")
        elif "test/validation" in bl:
            actions.append("Document validation steps (pre/post) and assign a validation owner.")
        elif "operational ownership" in bl:
            actions.append("Confirm ownership/on-call and update runbooks, dashboards, and alerts.")
        elif "blast radius" in bl:
            actions.append("Document blast radius and customer impact; define comms plan if needed.")
        elif "approvals" in bl:
            actions.append("Confirm approvals needed and lead time; schedule the change window accordingly.")
    return actions

def _verdict_reason(verdict: str, score: int, blockers: List[str], mode: str) -> str:
    if verdict == "BLOCKED":
        top = "; ".join(blockers[:3])
        return f"BLOCKED because key readiness items are missing ({top})."
    if verdict == "CONDITIONAL":
        return f"CONDITIONAL: score is {score}/10; proceed only after addressing recommended follow-ups."
    if mode == "security_reviewer":
        return f"APPROVED: sufficient controls described for a {mode} review (score {score}/10)."
    return f"APPROVED: plan includes rollback, validation, and ownership signals (score {score}/10)."

def _infer_signals(plan: str, context: Optional[str]) -> Signals:
    text = f"{plan}\n{context or ''}".lower()
    
    env = "unknown"
    if any(x in text for x in ["prod", "production", "customer-facing", "customer facing", "24/7", "24x7"]):
        env = "prod"
    elif "non-prod" in text or "nonprod" in text or "dev" in text or "test" in text:
        env = "non-prod"

    touches_auth = any(x in text for x in ["mfa", "iam", "role", "permission", "auth", "authentication", "authorization"])
    touches_data = any(x in text for x in ["database", "rds", "migration", "schema", "data", "snapshot", "restore"])

    change_type = "unknown"
    if touches_auth and any(x in text for x in ["disable", "turn off", "remove", "bypass", "skip"]):
        change_type = "security_exception"
    elif any(x in text for x in ["migrate", "migration", "cutover", "replication"]):
        change_type = "migration"
    elif any(x in text for x in ["save money", "downsize", "rightsizing", "cost", "savings plan", "reserved instance"]):
        change_type = "cost"
    elif any(x in text for x in ["deploy", "release", "rollout", "blue/green", "canary"]):
        change_type = "deploy"

    rollout = "unknown"
    if "canary" in text or "5%" in text or "10%" in text:
        rollout = "canary"
    elif "blue/green" in text or "blue-green" in text:
        rollout = "bluegreen"
    elif any(x in text for x in ["big bang", "all at once", "everything at once"]):
        rollout = "bigbang"

    return Signals(env=env, change_type=change_type, touches_auth=touches_auth, touches_data=touches_data, rollout=rollout)

# LLM Client for suggestions
class LLMClient:
    def __init__(self, provider: LLMProvider = "stub", bedrock_region: str = DEFAULT_BEDROCK_REGION,
                 bedrock_model_id: str = DEFAULT_BEDROCK_MODEL_ID, temperature: float = DEFAULT_BEDROCK_TEMPERATURE,
                 max_tokens: int = DEFAULT_BEDROCK_MAX_TOKENS) -> None:
        self.provider = provider
        self.bedrock_region = bedrock_region
        self.bedrock_model_id = bedrock_model_id
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._brt = None
        self.last_call_meta: Dict[str, Any] = {}
    
    def _bedrock(self):
        if self._brt is None:
            self._brt = boto3.client("bedrock-runtime", region_name=self.bedrock_region)
        return self._brt
    
    def generate_suggestions(self, plan: str, context: Optional[str], mode: ReviewerMode,
                           verdict: str, evidence: Dict[str, bool], signals: Signals,
                           suggestion_budget: SuggestionBudget) -> Dict[str, Any]:
        if self.provider == "bedrock":
            return self._bedrock_suggestions(plan, context, mode, verdict, evidence, signals, suggestion_budget)
        return self._stub_suggestions(plan, context, mode, verdict, evidence, signals)
    
    def _stub_suggestions(self, plan: str, context: Optional[str], mode: ReviewerMode,
                         verdict: str, evidence: Dict[str, bool], signals: Signals) -> Dict[str, Any]:
        sug_risks: List[Dict[str, Any]] = []
        sug_qs: List[Dict[str, Any]] = []
        sug_tests: List[Dict[str, Any]] = []
        
        def add_risk(title: str, why: str, category: str, anchor: Optional[str] = None) -> None:
            sug_risks.append({"title": title, "why": _strip_blocker_language(why), "category": category, "anchor": anchor})
        
        def add_q(title: str, why: str, category: str, anchor: Optional[str] = None) -> None:
            sug_qs.append({"title": title, "why": _strip_blocker_language(why), "category": category, "anchor": anchor})
        
        def add_test(title: str, why: str, category: str, anchor: Optional[str] = None) -> None:
            sug_tests.append({"title": title, "why": _strip_blocker_language(why), "category": category, "anchor": anchor})
        
        if signals.env == "prod":
            add_risk("Hidden peak-hour impact", "Even safe-looking changes can behave differently under peak traffic; consider peak-hour load and retries.", "reliability", anchor="production")
            add_test("Peak-hour smoke test", "Run smoke tests during a representative load period (or replay traffic) to catch latency/timeouts.", "performance", anchor="24/7")
        
        if signals.rollout in ("bluegreen", "canary"):
            add_test("Rollback rehearsal in lower env", "Practice the rollback path once to confirm timings and that dependencies revert cleanly.", "operations", anchor=signals.rollout)
        
        if signals.change_type == "security_exception" or signals.touches_auth:
            add_risk("Privilege creep", "Temporary access changes can linger; confirm expiry and monitoring so it doesn't quietly become permanent.", "security", anchor="MFA/IAM")
            add_q("Exception expiry + owner", "Who owns the exception and when does it auto-expire? Add compensating controls if needed.", "compliance", anchor="exception")
            add_test("Access path validation", "Validate that admin access still requires strong identity controls (or compensating controls) post-change.", "security", anchor="MFA")
        
        if signals.change_type == "migration" or signals.touches_data:
            add_risk("Data consistency edge cases", "Replication lag or schema drift can cause subtle data issues; consider consistency checks.", "reliability", anchor="migration/data")
            add_test("Data reconciliation check", "Run a small reconciliation/row-count/hash check before and after cutover.", "operations", anchor="database")
            add_q("RPO/RTO confirmation", "Confirm RPO/RTO expectations and validate backup/restore steps align with them.", "reliability", anchor="restore/backup")
        
        if signals.change_type == "cost":
            add_risk("False savings due to cost shifting", "Savings may move to data transfer, support effort, or latency; track end-to-end cost impact.", "finops", anchor="cost optimisation")
            add_test("Before/after measurement window", "Measure a clean before/after window and include seasonality or workload drift where possible.", "finops", anchor="baseline")
        
        if mode == "delivery_manager":
            add_q("Stakeholder comms plan", "Who needs to be informed, and what's the comms plan if rollback is triggered?", "delivery", anchor="change")
        
        if mode == "principal_engineer":
            add_q("Failure mode review", "What happens if a dependency (DB, cache, third-party) degrades mid-deploy? Consider partial failure behaviour.", "reliability", anchor="dependencies")
        
        return {"suggested_risks": sug_risks, "suggested_missing_questions": sug_qs, "suggested_tests": sug_tests}
    
    def _bedrock_suggestions(self, plan: str, context: Optional[str], mode: ReviewerMode,
                           verdict: str, evidence: Dict[str, bool], signals: Signals,
                           suggestion_budget: SuggestionBudget) -> Dict[str, Any]:
        self.last_call_meta = {"enabled": True, "provider": "bedrock", "model_id": self.bedrock_model_id, "region": self.bedrock_region, "status": "init"}
        
        if not self.bedrock_model_id:
            self.last_call_meta.update({"status": "skipped_missing_model_id"})
            return {"suggested_risks": [], "suggested_missing_questions": [], "suggested_tests": []}
        
        max_items = {"low": 2, "med": 4, "high": 6}[suggestion_budget]
        
        system_prompt = (
            "You are a brainstorming assistant for change reviews.\n"
            "You MUST return ONLY valid JSON. No markdown. No extra text.\n"
            "Do not use language like 'BLOCK' or 'REJECT'. Suggestions are optional.\n"
            "Your JSON MUST match this schema exactly:\n"
            "{"
            '  "suggested_risks":[{"title":str,"why":str,"category":str,"anchor":str|null}],'
            '  "suggested_missing_questions":[{"title":str,"why":str,"category":str,"anchor":str|null}],'
            '  "suggested_tests":[{"title":str,"why":str,"category":str,"anchor":str|null}]'
            "}\n"
            f"Allowed categories: {', '.join(sorted(ALLOWED_SUGGESTION_CATEGORIES))}.\n"
            f"Max {max_items} items per list.\n"
            "Make each 'why' specific, short, and grounded in the provided plan/context.\n"
        )
        
        user_payload = {"mode": mode, "verdict": verdict, "signals": signals.__dict__, "evidence": evidence, "plan": plan, "context": context or ""}
        
        t0 = time.time()
        
        try:
            resp = self._bedrock().converse(
                modelId=self.bedrock_model_id,
                system=[{"text": system_prompt}],
                messages=[{"role": "user", "content": [{"text": json.dumps(user_payload)}]}],
                inferenceConfig={"maxTokens": self.max_tokens, "temperature": self.temperature}
            )
        except (ClientError, BotoCoreError) as e:
            self.last_call_meta.update({"status": "error", "error": f"{type(e).__name__}: {str(e)[:200]}"})
            return {"suggested_risks": [], "suggested_missing_questions": [], "suggested_tests": []}
        
        latency_ms = int((time.time() - t0) * 1000)
        req_id = resp.get("ResponseMetadata", {}).get("RequestId")
        
        self.last_call_meta.update({"status": "ok", "latency_ms": latency_ms, "request_id": req_id})
        
        out_text = ""
        try:
            for part in resp.get("output", {}).get("message", {}).get("content", []):
                if "text" in part:
                    out_text += part["text"]
        except Exception:
            self.last_call_meta.update({"parse_status": "error", "parse_error": "failed_extract_text"})
            return {"suggested_risks": [], "suggested_missing_questions": [], "suggested_tests": []}
        
        self.last_call_meta["response_chars"] = len(out_text or "")
        
        parsed = _extract_first_json_object(out_text)
        if not parsed:
            self.last_call_meta.update({"parse_status": "error", "parse_error": "no_json_found"})
            return {"suggested_risks": [], "suggested_missing_questions": [], "suggested_tests": []}
        
        self.last_call_meta.update({"parse_status": "ok"})
        return parsed

def _get_suggestions_v2(plan: str, context: Optional[str], mode: ReviewerMode, verdict: str,
                       evidence: Dict[str, bool], signals: Signals, enable_llm_suggestions: bool,
                       llm_provider: LLMProvider, suggestion_budget: SuggestionBudget,
                       cache_dir: str, cache_ttl_seconds: int, cache_enabled: bool,
                       bedrock_region: str, bedrock_model_id: str, bedrock_temperature: float,
                       bedrock_max_tokens: int) -> Tuple[Optional[Suggestions], Dict[str, Any]]:
    meta: Dict[str, Any] = {"enabled": enable_llm_suggestions, "provider": llm_provider}
    if llm_provider == "bedrock":
        meta.update({"model_id": bedrock_model_id, "region": bedrock_region})
    
    if not enable_llm_suggestions:
        meta["status"] = "disabled"
        meta["cached"] = False
        return None, meta
    
    key = _hash_key(["v2_suggestions", plan, context or "", mode, verdict,
                    json.dumps(evidence, sort_keys=True), json.dumps(signals.__dict__, sort_keys=True),
                    suggestion_budget, llm_provider, bedrock_region, bedrock_model_id])
    
    if cache_enabled:
        cached = _cache_read(cache_dir, key, cache_ttl_seconds)
        if cached:
            meta["status"] = "ok"
            meta["cached"] = True
            try:
                cached.pop("_cached_at", None)
                s = Suggestions.model_validate(cached).bounded(suggestion_budget)
                s = Suggestions(
                    suggested_risks=_dedupe_items(s.suggested_risks),
                    suggested_missing_questions=_dedupe_items(s.suggested_missing_questions),
                    suggested_tests=_dedupe_items(s.suggested_tests)
                )
                return s, meta
            except Exception:
                meta["status"] = "ignored_invalid_cache_schema"
    
    client = LLMClient(provider=llm_provider, bedrock_region=bedrock_region, bedrock_model_id=bedrock_model_id,
                      temperature=bedrock_temperature, max_tokens=bedrock_max_tokens)
    raw = client.generate_suggestions(plan, context, mode, verdict, evidence, signals, suggestion_budget)
    
    if isinstance(getattr(client, "last_call_meta", None), dict):
        meta.update({k: v for k, v in client.last_call_meta.items() if v is not None})
    
    try:
        s = Suggestions.model_validate(raw).bounded(suggestion_budget)
        s = Suggestions(
            suggested_risks=_dedupe_items(s.suggested_risks),
            suggested_missing_questions=_dedupe_items(s.suggested_missing_questions),
            suggested_tests=_dedupe_items(s.suggested_tests)
        )
        meta["status"] = "ok"
        meta["cached"] = False
        if cache_enabled:
            _cache_write(cache_dir, key, s.model_dump())
        return s, meta
    except Exception:
        meta["status"] = "ignored_invalid_llm_schema"
        return None, meta

def review_gate(
    plan: str,
    context: Optional[str] = None,
    mode: ReviewerMode = "principal_engineer",
    strict: bool = True,
    output_level: OutputLevel = "auto",
    max_followups: int = 3,
    enable_llm_suggestions: bool = True,
    llm_provider: LLMProvider = "bedrock",
    suggestion_budget: SuggestionBudget = "low",
    suggestion_cache_enabled: bool = False,
    suggestion_cache_dir: str = DEFAULT_CACHE_DIR,
    suggestion_cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    bedrock_region: str = DEFAULT_BEDROCK_REGION,
    bedrock_model_id: str = DEFAULT_BEDROCK_MODEL_ID,
    bedrock_temperature: float = DEFAULT_BEDROCK_TEMPERATURE,
    bedrock_max_tokens: int = DEFAULT_BEDROCK_MAX_TOKENS,
) -> Dict[str, Any]:
    """Complete review gate function with LLM suggestions"""
    
    overrides = _mode_overrides(mode)
    evidence = _detect_evidence(plan, context)
    score = _score_from_evidence(evidence)
    blockers = _blockers_from_evidence(evidence, mode)

    if strict and blockers:
        verdict: str = "BLOCKED"
    else:
        verdict = "APPROVED" if score >= 7 else "CONDITIONAL"

    if output_level == "auto":
        if verdict == "APPROVED":
            level: OutputLevel = "summary"
        elif verdict == "CONDITIONAL":
            level = "review"
        else:
            level = "diagnostic"
    else:
        level = output_level

    required_actions = list(overrides["required_actions"])
    required_actions.extend(_actions_from_blockers(blockers))
    reason = _verdict_reason(verdict, score, blockers, mode)
    signals = _infer_signals(plan, context)

    # Get LLM suggestions
    suggestions, llm_meta = _get_suggestions_v2(
        plan=plan, context=context, mode=mode, verdict=verdict, evidence=evidence, signals=signals,
        enable_llm_suggestions=enable_llm_suggestions, llm_provider=llm_provider,
        suggestion_budget=suggestion_budget, cache_dir=suggestion_cache_dir,
        cache_ttl_seconds=suggestion_cache_ttl_seconds, cache_enabled=suggestion_cache_enabled,
        bedrock_region=bedrock_region, bedrock_model_id=bedrock_model_id,
        bedrock_temperature=bedrock_temperature, bedrock_max_tokens=bedrock_max_tokens
    )

    # Build suggestion block
    suggested_block: Dict[str, Any] = {"llm_meta": llm_meta}
    if enable_llm_suggestions:
        if suggestions:
            suggested_block.update({
                "suggested_risks": [x.model_dump() for x in suggestions.suggested_risks],
                "suggested_missing_questions": [x.model_dump() for x in suggestions.suggested_missing_questions],
                "suggested_tests": [x.model_dump() for x in suggestions.suggested_tests]
            })
        else:
            suggested_block.update({
                "suggested_risks": [],
                "suggested_missing_questions": [],
                "suggested_tests": []
            })

    assumptions = _core_assumptions() + overrides["assumptions"]
    risks = _core_risks() + overrides["risks"]
    missing_inputs = _missing_inputs_from_evidence(evidence)
    tradeoff = _pick_tradeoff(mode)

    # Build response based on output level
    if level == "summary":
        out: Dict[str, Any] = {
            "mode": mode,
            "strict": strict,
            "output_level": level,
            "verdict": verdict,
            "score_out_of_10": score,
            "verdict_reason": reason,
            "blockers": blockers,
            "optional_followups": required_actions[:max(0, max_followups)],
            "tradeoff_forced": tradeoff,
            "evidence_detected": evidence
        }
        out.update(suggested_block)
        return out
    elif level == "review":
        out = {
            "mode": mode,
            "strict": strict,
            "output_level": level,
            "verdict": verdict,
            "score_out_of_10": score,
            "verdict_reason": reason,
            "blockers": blockers,
            "required_actions": required_actions[:max(0, max_followups)],
            "tradeoff_forced": tradeoff,
            "evidence_detected": evidence
        }
        out.update(suggested_block)
        out["notes"] = [
            "This is the balanced review view. Use output_level='diagnostic' for full detail.",
            "v2 suggestions (if enabled) are optional and do not affect the verdict."
        ]
        return out
    else:  # diagnostic
        out = {
            "mode": mode,
            "strict": strict,
            "output_level": level,
            "verdict": verdict,
            "score_out_of_10": score,
            "verdict_reason": reason,
            "blockers": blockers,
            "assumptions_to_challenge": assumptions,
            "key_risks": risks,
            "missing_inputs_checklist": missing_inputs,
            "tradeoff_forced": tradeoff,
            "required_actions": required_actions,
            "evidence_detected": evidence,
            "signals": signals.__dict__
        }
        out.update(suggested_block)
        out["notes"] = [
            "Tip: Update the plan/context with missing items and rerun review_gate to see the verdict improve.",
            "This output is deterministic for verdict/blockers and does not depend on chat memory.",
            "Use output_level='summary' for concise output when you just want the decision.",
            "v2 suggestions (if enabled) are optional brainstorming and never affect the verdict.",
            "For Bedrock: set env vars BEDROCK_MODEL_ID (required) and optionally BEDROCK_REGION."
        ]
        return out