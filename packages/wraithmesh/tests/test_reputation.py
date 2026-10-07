from wraithmesh.reputation import INITIAL_REPUTATION, ReputationStore


def test_reputation_grows_on_corroboration():
    store = ReputationStore()
    store.record_submission("node_a", sensor_class="cowrie")
    store.record_submission("node_b", sensor_class="cowrie")
    store.record_corroboration("node_a")
    store.record_corroboration("node_b")
    assert store.get("node_a").score > INITIAL_REPUTATION
    assert store.get("node_b").score > INITIAL_REPUTATION


def test_canary_weight_beats_cowrie():
    store = ReputationStore()
    cowrie = store.record_submission("c", sensor_class="cowrie")
    canary = store.record_submission("k", sensor_class="canary")
    assert canary > cowrie