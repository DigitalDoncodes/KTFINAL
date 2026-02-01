from collections import defaultdict

# ---------- Likert Scale ----------
LIKERT_MAP = {
    "Strongly Disagree": 1,
    "Disagree": 2,
    "Neutral": 3,
    "Agree": 4,
    "Strongly Agree": 5
}

# ---------- Domain interpretations ----------
DOMAIN_INTERPRETATIONS = {
    "emotional_awareness": {
        "high": "You demonstrate strong emotional insight and awareness of your internal states.",
        "medium": "You show moderate awareness of your emotions, with room for deeper reflection.",
        "low": "You may benefit from practices that help identify and understand emotions."
    },
    "stress_management": {
        "high": "You appear to manage stress effectively and adapt well under pressure.",
        "medium": "You manage stress reasonably well, though some situations may feel overwhelming.",
        "low": "Stress may feel difficult to handle at times; structured coping strategies could help."
    }
}

# ---------- Helpers ----------
def interpret_score(score):
    if score >= 4:
        return "high"
    elif score >= 2.5:
        return "medium"
    else:
        return "low"


def calculate_domain_scores(responses):
    """
    responses = [
      { "domain": "emotional_awareness", "answer": "Agree" },
      ...
    ]
    """
    domain_totals = defaultdict(list)

    for r in responses:
        score = LIKERT_MAP.get(r["answer"], 3)
        domain_totals[r["domain"]].append(score)

    domain_scores = {
        domain: round(sum(values) / len(values), 2)
        for domain, values in domain_totals.items()
    }

    return domain_scores


def generate_insight_summary(domain_scores):
    insights = {}

    for domain, data in domain_scores.items():
        avg = data["average"]  # ✅ extract number

        level = interpret_score(avg)

        if level == "High":
            insights[domain] = "Strong strength 💪"
        elif level == "Moderate":
            insights[domain] = "Stable but improvable 👍"
        elif level == "Low":
            insights[domain] = "Needs focused attention ⚠️"
        else:
            insights[domain] = "Critical area 🚨"

    return insights