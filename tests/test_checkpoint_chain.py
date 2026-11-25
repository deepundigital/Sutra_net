import copy

import pytest

from sutra_net.compliance.trusted_checkpoint import (
    CheckpointChainError,
    analyze_sequence_gaps,
    create_checkpoint,
    generate_keypair,
    sign_checkpoint,
    verify_checkpoint_chain,
)


@pytest.fixture
def keypair():
    return generate_keypair()


def seal_chain(private_key, ledger_id="case-chain-ledger", sequences=(1, 2, 3)):
    envelopes = []
    for index, sequence in enumerate(sequences):
        checkpoint = create_checkpoint(
            ledger_id=ledger_id,
            sequence=sequence,
            last_entry_hash="d" * 64,
            signing_key_id="chain-key-01",
            timestamp_utc=f"2026-11-03T06:00:{index:02d}Z",
        )
        envelopes.append(sign_checkpoint(checkpoint, private_key))
    return envelopes


def test_single_checkpoint_chain_is_valid(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(0,))

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is True
    assert report["count"] == 1
    assert report["last_sequence"] == 0


def test_ordered_multi_checkpoint_chain_is_valid(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(1, 2, 3))

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is True
    assert report["count"] == 3
    assert report["first_sequence"] == 1
    assert report["last_sequence"] == 3
    assert report["gaps"] == []
    assert report["last_digest"] is not None


def test_unsorted_input_still_verifies_but_detects_gaps(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(1, 5, 2))

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    # 5 followed by 2 regresses in the claimed append order.
    assert report["valid"] is False
    assert report["sequence_regressions"] == [[5, 2]]


def test_tampered_middle_envelope_invalidates_chain(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(1, 2, 3))
    tampered = copy.deepcopy(envelopes[1])
    tampered["checkpoint"]["last_entry_hash"] = "e" * 64
    tampered["signature"] = envelopes[1]["signature"]
    envelopes[1] = tampered

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is False
    assert any("position 1" in error for error in report["errors"])


def test_unknown_signing_key_invalidates_chain(keypair):
    private_key, _ = keypair
    _, stranger_public = generate_keypair()
    envelopes = seal_chain(private_key)

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": stranger_public})

    assert report["valid"] is False
    assert report["count"] == 0


def test_mixed_ledger_ids_rejected(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(1, 2))
    other = sign_checkpoint(
        create_checkpoint(
            ledger_id="other-ledger",
            sequence=3,
            last_entry_hash="d" * 64,
            signing_key_id="chain-key-01",
            timestamp_utc="2026-11-03T06:00:05Z",
        ),
        private_key,
    )
    envelopes.append(other)

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is False
    assert any("ledger" in error for error in report["errors"])


def test_duplicate_sequence_is_fork_evidence(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(1, 2, 2))

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is False
    assert report["duplicates"] == [2]


def test_rollback_sequence_rejected(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(5, 4))

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is False
    assert report["sequence_regressions"] == [[5, 4]]
    assert any("rollback" in error for error in report["errors"])


def test_timestamp_regression_rejected(keypair):
    private_key, public_key = keypair
    later_first = sign_checkpoint(
        create_checkpoint(
            ledger_id="case-chain-ledger",
            sequence=1,
            last_entry_hash="d" * 64,
            signing_key_id="chain-key-01",
            timestamp_utc="2026-11-03T07:00:00Z",
        ),
        private_key,
    )
    earlier_second = sign_checkpoint(
        create_checkpoint(
            ledger_id="case-chain-ledger",
            sequence=2,
            last_entry_hash="d" * 64,
            signing_key_id="chain-key-01",
            timestamp_utc="2026-11-03T06:00:00Z",
        ),
        private_key,
    )

    report = verify_checkpoint_chain(
        [later_first, earlier_second], {"chain-key-01": public_key}
    )

    assert report["valid"] is False
    assert report["timestamp_regressions"] == [[1, 2]]


def test_equal_timestamps_are_allowed(keypair):
    private_key, public_key = keypair
    envelopes = []
    for sequence in (1, 2):
        envelopes.append(
            sign_checkpoint(
                create_checkpoint(
                    ledger_id="case-chain-ledger",
                    sequence=sequence,
                    last_entry_hash="d" * 64,
                    signing_key_id="chain-key-01",
                    timestamp_utc="2026-11-03T06:00:00Z",
                ),
                private_key,
            )
        )

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is True


def test_gaps_are_informational_not_fatal(keypair):
    private_key, public_key = keypair
    envelopes = seal_chain(private_key, sequences=(1, 2, 7))

    report = verify_checkpoint_chain(envelopes, {"chain-key-01": public_key})

    assert report["valid"] is True
    assert report["gaps"] == [[2, 7]]


def test_empty_chain_is_trivially_valid():
    report = verify_checkpoint_chain([], {})

    assert report["valid"] is True
    assert report["count"] == 0


def test_non_list_input_raises():
    with pytest.raises(CheckpointChainError):
        verify_checkpoint_chain("not a list", {})


def test_non_dict_element_reported_not_raised(keypair):
    _, public_key = keypair

    report = verify_checkpoint_chain(["junk"], {"chain-key-01": public_key})

    assert report["valid"] is False
    assert report["count"] == 0


def test_analyze_sequence_gaps_utility():
    assert analyze_sequence_gaps([1, 2, 5, 9]) == [[2, 5], [5, 9]]
    assert analyze_sequence_gaps([]) == []
    assert analyze_sequence_gaps([4, 4, 4]) == []

    with pytest.raises(CheckpointChainError):
        analyze_sequence_gaps(["1", 2])
