"""Integrity checks for the Round-2 prototype submission deck."""

from pathlib import Path

import pytest
from pptx import Presentation

DECK = (
    Path(__file__).resolve().parent.parent
    / "deck"
    / "SUTRAM_2026_Prototype_Submission_SutraNet.pptx"
)

NEW_TITLES = [
    "ROUND 2 ALIGNMENT: SUTRAMPS04",
    "SIGNED CHAIN-OF-CUSTODY CHECKPOINTS",
    "LIVE SCENARIO DEMO & LEA ROADMAP",
]

# Largest body on the original template content slides is 1665 chars; the
# template rule of thumb allows 10% headroom on any box we refill.
BODY_BUDGET = int(1665 * 1.1)


@pytest.fixture(scope="module")
def deck():
    return Presentation(str(DECK))


def all_text(prs):
    out = []
    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                out.append(shape.text_frame.text)
    return out


def test_deck_has_exactly_ten_slides(deck):
    """The template's own rule: maximum ten slides including the title."""

    assert len(deck.slides) == 10


def test_title_slide_carries_round2_mapping(deck):
    title = deck.slides[0]
    assert title.shapes[9].text_frame.text.strip() == "SUTRAMPS04"
    assert title.shapes[17].text_frame.text.strip() == "Team SutraNet"
    assert title.shapes[4].text_frame.text.strip() == "ROUND 2"


def test_no_template_instruction_slide(deck):
    joined = "\n".join(all_text(deck))
    assert "IMPORTANT INSTRUCTIONS" not in joined
    assert "Click to add" not in joined


def test_no_unfilled_team_tags(deck):
    tags = [t for t in all_text(deck) if "Team:" in t and "___" in t]
    assert tags == []


def test_new_round2_slides_present_with_bodies_in_budget(deck):
    for offset, expected_title in enumerate(NEW_TITLES):
        slide = deck.slides[7 + offset]
        assert slide.shapes[4].text_frame.text.strip() == expected_title

        body = slide.shapes[7].text_frame.text
        assert len(body) > 500
        assert len(body) <= BODY_BUDGET, (
            f"{expected_title} body over template budget: {len(body)}"
        )


def test_all_picture_relationships_resolve(deck):
    """Cloned slides remap image rIds; every rel must resolve to real bytes."""

    for slide in deck.slides:
        for rel in slide.part.rels.values():
            if not rel.is_external:
                assert len(rel.target_part.blob) > 0
