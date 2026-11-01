"""A guard that fails in a loop writes one traceback, not one per pass."""
from src import faults


def _raise():
    try:
        raise ValueError("boom")
    except ValueError as exc:
        return exc


def test_the_same_fault_is_written_once_in_a_row(capsys):
    exc = _raise()
    for _ in range(50):
        faults.note("a section", exc)
    faults.note("another section", exc)
    err = capsys.readouterr().err
    assert err.count("a section failed") == 1
    assert err.count("another section failed") == 1


def test_a_quiet_place_says_how_many_it_swallowed(capsys):
    exc = _raise()
    for _ in range(5):
        faults.note("a section", exc)
    faults._places["a section"][0] -= faults.QUIET_SECONDS + 1
    faults.note("a section", exc)
    assert "failed again, 4 time(s)" in capsys.readouterr().err


def test_the_places_remembered_are_bounded():
    exc = _raise()
    for index in range(faults.MAX_PLACES * 3):
        faults.note(f"place {index}", exc)
    assert len(faults._places) <= faults.MAX_PLACES


def test_the_log_hears_every_one_even_when_stderr_does_not():
    heard = []
    faults.watch(lambda where, exc: heard.append(where))
    try:
        exc = _raise()
        for _ in range(10):
            faults.note("a section", exc)
    finally:
        faults.watch(None)
    assert len(heard) == 10
