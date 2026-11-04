from flagwatch.analysis.evidence import EvidenceDocument
from flagwatch.analysis.facts import extract_event_facts
from flagwatch.domain import EventFacts, ScheduleMode


def test_extracts_team_divisions_and_staggered_schedule():
    documents = [
        EvidenceDocument(
            "https://ctf.example/rules",
            "Teams can include up to 6 members. Divisions: Student, Open. "
            "Teams receive staggered start times.",
        )
    ]

    facts = extract_event_facts(documents, EventFacts())

    assert facts.team_max == 6
    assert facts.divisions == ["Student", "Open"]
    assert facts.schedule_mode is ScheduleMode.STAGGERED


def test_detects_multi_stage_without_overwriting_seed_prize():
    seed = EventFacts(prize_summary="$1,000 total")
    documents = [
        EvidenceDocument(
            "https://ctf.example/about",
            "The online qualification round is followed by an in-person final stage.",
        )
    ]

    facts = extract_event_facts(documents, seed)

    assert facts.schedule_mode is ScheduleMode.MULTI_STAGE
    assert facts.prize_summary == "$1,000 total"


def test_extracts_diverse_team_sizes_and_solo():
    doc_solo = EvidenceDocument("https://ctf.example/rules", "This is an individual competition.")
    assert extract_event_facts([doc_solo], EventFacts()).team_max == 1

    doc_size = EvidenceDocument("https://ctf.example/rules", "Team size: 4. Open division.")
    assert extract_event_facts([doc_size], EventFacts()).team_max == 4

    doc_limit = EvidenceDocument("https://ctf.example/rules", "Maximum team size: five players per team.")
    assert extract_event_facts([doc_limit], EventFacts()).team_max == 5

    doc_range = EvidenceDocument("https://ctf.example/rules", "Teams of 1-4 players allowed.")
    assert extract_event_facts([doc_range], EventFacts()).team_max == 4


def test_extracts_categories_prizes_and_registration_links():
    documents = [
        EvidenceDocument(
            "https://ctf.example/event",
            "Categories include Web, Crypto, Pwn, Reverse Engineering, and Forensics.\n"
            "Prizes: First place $2,500, Second place $1,000, plus custom swag for top 10.\n"
            "Register at https://ctf.example.org/register now!\n"
            "Join our Discord at https://discord.gg/kernelkittens for live updates.",
        )
    ]

    facts = extract_event_facts(documents, EventFacts())

    assert "Web" in facts.categories
    assert "Crypto" in facts.categories
    assert "Pwn" in facts.categories
    assert "Reverse Engineering" in facts.categories
    assert "Forensics" in facts.categories
    assert facts.prize_summary is not None
    assert "$2,500" in facts.prize_summary
    claims = {claim.label: claim.value for claim in facts.intel_claims}
    assert "Registration Link" in claims
    assert "https://ctf.example.org/register" in claims["Registration Link"]
    assert "Community Discord" in claims
    assert "https://discord.gg/kernelkittens" in claims["Community Discord"]
