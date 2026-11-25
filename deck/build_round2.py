"""Round-2 prototype deck builder for the SUTRAM 2026 official template.

Takes the populated Round-1 deck (SUTRAM_2026_Idea_Submission_SutraNet.pptx)
and produces the Round-2 prototype submission deck as a NEW file:

  - deletes the template's "IMPORTANT INSTRUCTIONS" slide (the template
    itself says to remove it before uploading),
  - fills the two title-slide placeholders the Round-1 deck left as em-dashes
    (problem-statement ID and team name),
  - appends exactly three content slides cloned from the standard content
    layout: PS04 alignment, signed chain-of-custody, demo + LEA roadmap,
    honouring the template's hard rule of ten slides maximum.

The Round-1 artifact is never modified.
"""

import copy
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.oxml.ns import qn
from pptx.util import Pt

DECK_DIR = Path(__file__).resolve().parent
SOURCE_DECK = DECK_DIR / "SUTRAM_2026_Idea_Submission_SutraNet.pptx"
OUTPUT_DECK = DECK_DIR / "SUTRAM_2026_Prototype_Submission_SutraNet.pptx"

TEAM_NAME = "Team SutraNet"
PS_ID = "SUTRAMPS04"
FOOTER_TEXT = "Prototype Submission  ·  Where Every Trace Connects"

HEADING_RGB = RGBColor(30, 58, 138)   # deep navy (matches Round-1 body headings)
BODY_RGB = RGBColor(30, 41, 59)

NEW_SLIDES = [
    (
        "09",
        "ROUND 2 ALIGNMENT: SUTRAMPS04",
        [
            ("Primary - SUTRAMPS04: Cyber Fraud Investigation & Attribution",
             "Chitra-NLP extracts UPI VPAs (@okaxis/@paytm/@ybl), Indian phone numbers, IFSC codes and bank UTR references from seized chats; the NetworkX graph attributes high-degree mule accounts and cash-out chains."),
            ("Supporting - SUTRAMPS03: Evidence Correlation & Reconstruction",
             "One temporal knowledge graph joins network flows, handsets, burner SIMs and C2 infrastructure; DuckDB timeline queries reconstruct the crime window in sub-seconds."),
            ("Supporting - SUTRAMPS01: Mobile Evidence Intelligence",
             "msgstore/mmssms parsers recover WhatsApp/SMS artifacts with per-message scam categorisation and behavioural profiling."),
            ("Rubric Fit",
             "Six of ten evaluation criteria are forensics-specific; signed chain-of-custody checkpoints serve Investigation Accuracy, Traceability & Explainability directly."),
            ("Round-2 Deliverables",
             "Working prototype with a 176-test suite, updated abstract, executable scenario demo, LEA deployment roadmap and this submission deck - all under the single SUTRAMPS04 mapping."),
        ],
    ),
    (
        "10",
        "SIGNED CHAIN-OF-CUSTODY CHECKPOINTS",
        [
            ("Ed25519-Sealed Ledger States",
             "The audit ledger's verified tail is frozen into signed checkpoints: canonical JSON, deterministic digests, exact 64-byte signature enforcement and SHA-256 fingerprint-pinned public keys."),
            ("Immutable Owner-Only Store",
             "Atomic writes (temp + fsync + atomic rename), strict filename grammar with payload fingerprints, owner-only permissions, symlink and overwrite refusal - stored evidence is never silently rewritten."),
            ("Rollback & Fork Detection",
             "Chain verification enforces one ledger, strictly increasing sequences and monotonic timestamps; repeats are fork evidence, regressions are rollback evidence - provable offline from signatures alone."),
            ("Operator Workflow",
             "python -m sutra_net.compliance.trusted_checkpoint keygen | seal | verify | list, or three authenticated dashboard routes; signing keys are passphrase-encryptable at rest (PBES2) and never stored beside the registry."),
            ("Engineering Rigour",
             "176 automated tests across storage, keyring, chain, API, CLI and adversarial batteries; ~570 seals/second and a 16 ms full-chain audit of 200 checkpoints."),
        ],
    ),
    (
        "11",
        "LIVE SCENARIO DEMO & LEA ROADMAP",
        [
            ("Demo Stages 1-2 - Acquisition & Network Triage",
             "Seized PCAP/handset DB hashed (SHA-256/SHA-3) into the ledger; encrypted C2 beaconing flagged by jitter, entropy and JA3 - without decrypting TLS 1.3."),
            ("Demo Stages 3-4 - Mobile Triage & Correlation",
             "Hinglish extortion chats categorised (coercion, urgency, OTP); UPI VPAs, phones and mule accounts resolved onto one knowledge graph."),
            ("Demo Stages 5-6 - Custody & Certification",
             "Ledger tail sealed as a signed checkpoint; chain verified; one-click Sec-63 certificate embeds live hash re-verification. The demo exits 0 only if chain verification passes."),
            ("Roadmap A-B - Pilot to State Roll-Out (0-9 months)",
             "2 FSL labs, then 10-20 workstations: checkpoint sealing as SOP, nightly offline chain audits, dual-control key ceremony."),
            ("Roadmap C-D - Federation to National (9-18+ months)",
             "Cross-lab checkpoint exchange re-verified against pinned keys; C-DAC/MeitY packaging, NFSU validation, ISEA training; zero licence fees."),
            ("Reproducibility",
             "python3 demo/run_scenario.py - six-stage JSON timeline, fully offline."),
        ],
    ),
]


def delete_slide(prs, index: int) -> None:
    """Remove a slide by index (call high-index first)."""

    sld = list(prs.slides._sldIdLst)[index]
    prs.part.drop_rel(sld.get(qn("r:id")))
    prs.slides._sldIdLst.remove(sld)


def clone_slide(prs, source):
    """Append a deep copy of source, remapping every picture relationship."""

    dest = prs.slides.add_slide(source.slide_layout)

    # Drop any empty placeholders the layout injected: this template draws
    # everything with real text boxes on the slide itself.
    for ph in list(dest.placeholders):
        ph._element.getparent().remove(ph._element)

    for shp in source.shapes:
        el = copy.deepcopy(shp._element)
        for node in el.iter():
            for attr in (qn("r:embed"), qn("r:link"), qn("r:id")):
                rid = node.get(attr)
                if not rid:
                    continue
                rel = source.part.rels[rid]
                if rel.is_external:
                    new_rid = dest.part.rels.get_or_add_ext_rel(
                        rel.reltype, rel.target_ref
                    )
                else:
                    new_rid = dest.part.relate_to(rel.target_part, rel.reltype)
                node.set(attr, new_rid)
        dest.shapes._spTree.append(el)

    return dest


def replace_text_keep_format(shape, text: str) -> None:
    """First-run text replacement so inherited formatting survives."""

    tf = shape.text_frame
    p = tf.paragraphs[0]
    if p.runs:
        p.runs[0].text = text
        for r in p.runs[1:]:
            r._r.getparent().remove(r._r)
    else:
        p.text = text


def fill_body(shape, points, font_size: float = 10.5) -> None:
    """Replicates the Round-1 body style: navy bold lead-ins, dark body."""

    tf = shape.text_frame
    tf.clear()
    for i, (heading, body) in enumerate(points):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(6)

        run_title = p.add_run()
        run_title.text = f"▸ {heading}: "
        run_title.font.bold = True
        run_title.font.size = Pt(font_size)
        run_title.font.color.rgb = HEADING_RGB

        run_body = p.add_run()
        run_body.text = body
        run_body.font.bold = False
        run_title.font.size = Pt(font_size)
        run_body.font.size = Pt(font_size)
        run_body.font.color.rgb = BODY_RGB


def build() -> Path:
    prs = Presentation(str(SOURCE_DECK))
    source_body_budget = len(prs.slides[4].shapes[7].text_frame.text) * 1.1

    # 1. The template instructs deleting the instructions slide before upload.
    assert "IMPORTANT INSTRUCTIONS" in prs.slides[7].shapes[4].text_frame.text
    delete_slide(prs, 7)

    # 2. Fill the title-slide placeholders Round 1 left as em-dashes.
    title = prs.slides[0]
    replace_text_keep_format(title.shapes[4], "ROUND 2")
    replace_text_keep_format(title.shapes[9], PS_ID)
    replace_text_keep_format(title.shapes[17], TEAM_NAME)
    replace_text_keep_format(title.shapes[18], f"Team: {TEAM_NAME}")
    replace_text_keep_format(title.shapes[19], FOOTER_TEXT)

    # The old em-dash runs carry light placeholder styling; re-style the two
    # filled values to match the theme line (dark, bold) so they read as
    # real field values on a projector.
    theme_run = title.shapes[13].text_frame.paragraphs[0].runs[0]
    try:
        value_color = theme_run.font.color.rgb
    except AttributeError:  # theme-inherited color: fall back to ink navy
        value_color = RGBColor(15, 23, 42)

    for value_shape in (title.shapes[9], title.shapes[17]):
        run = value_shape.text_frame.paragraphs[0].runs[0]
        run.font.bold = True
        if theme_run.font.size is not None:
            run.font.size = theme_run.font.size
        run.font.color.rgb = value_color

    # 2b. Round 1 only filled the team tag on some slides; sweep every
    # leftover generic tag. Slide 2's member-detail fields are the team's
    # own data and are deliberately left untouched.
    for slide in prs.slides:
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
            text = shape.text_frame.text
            if "Team:" in text and "___" in text:
                replace_text_keep_format(shape, f"Team: {TEAM_NAME}")
            elif "Idea Submission  ·  Where Every Trace Connects" in text:
                replace_text_keep_format(shape, FOOTER_TEXT)

    # 3. Append the three Round-2 content slides (clones of slide 5).
    source = prs.slides[4]
    for page_no, slide_title, points in NEW_SLIDES:
        body_chars = sum(len(h) + len(b) for h, b in points)
        assert body_chars <= source_body_budget, (
            f"{slide_title} body {body_chars} exceeds budget {source_body_budget:.0f}"
        )

        slide = clone_slide(prs, source)
        replace_text_keep_format(slide.shapes[3], page_no)
        replace_text_keep_format(slide.shapes[4], slide_title)
        fill_body(slide.shapes[7], points)
        replace_text_keep_format(slide.shapes[8], f"Team: {TEAM_NAME}")
        replace_text_keep_format(slide.shapes[9], FOOTER_TEXT)
        replace_text_keep_format(slide.shapes[11], page_no)

    prs.save(str(OUTPUT_DECK))
    return OUTPUT_DECK


def verify(path: Path) -> None:
    """Programmatic QA per the template rules; raises on any violation."""

    prs = Presentation(str(path))
    assert len(prs.slides) == 10, f"expected 10 slides, got {len(prs.slides)}"

    all_text = []
    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                all_text.append(shape.text_frame.text)
    joined = "\n".join(all_text)

    assert "IMPORTANT INSTRUCTIONS" not in joined
    assert "Click to add" not in joined

    team_tags = [t for t in all_text if "Team:" in t and "___" in t]
    assert not team_tags, f"unfilled team tag survived: {team_tags[:3]}"

    first = prs.slides[0]
    assert first.shapes[9].text_frame.text.strip() == PS_ID
    assert first.shapes[17].text_frame.text.strip() == TEAM_NAME

    for offset, (_, slide_title, points) in enumerate(NEW_SLIDES):
        slide = prs.slides[7 + offset]
        assert slide.shapes[4].text_frame.text.strip() == slide_title
        body = slide.shapes[7].text_frame.text
        assert len(body) > 500, "body looks empty"

    # Every picture relationship on every slide must resolve to real bytes.
    for slide in prs.slides:
        for rel in slide.part.rels.values():
            if not rel.is_external:
                assert len(rel.target_part.blob) > 0

    print(f"verified: 10 slides, placeholders filled, {PS_ID} mapped, "
          f"3 new content slides, all image rels resolve")


if __name__ == "__main__":
    out = build()
    verify(out)
    print(f"Round-2 deck written to {out}")
