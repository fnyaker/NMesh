"""L'encodeur QR (stdlib pure).

Un encodeur QR maison ne vaut rien s'il ne se décode pas. Les vérifications
fortes — égalité module par module avec un encodeur indépendant, et décodage
réel — tournent quand l'outillage optionnel est installé ; sinon on vérifie ce
qui est vérifiable sans dépendance : structure, bornes, déterminisme.

    pip install qrcode opencv-python-headless numpy   # pour les tests forts
"""
import pytest

from src import qr
from src import join_ticket


def _ticket_text():
    return join_ticket.encode("203.0.113.7", 9000, b"\x01" * 8, 1_800_000_000)


class TestStructure:
    def test_the_matrix_is_square_and_binary(self):
        matrix = qr.encode("HELLO WORLD")
        assert len(matrix) == len(matrix[0])
        assert all(cell in (0, 1) for row in matrix for cell in row)

    def test_a_version_1_symbol_is_21_modules(self):
        assert len(qr.encode("A")) == 21

    def test_a_ticket_fits_in_a_small_symbol(self):
        """34 caractères alphanumériques doivent tenir en version 2."""
        assert len(qr.encode(_ticket_text())) == 25

    def test_the_finder_patterns_are_where_they_belong(self):
        matrix = qr.encode("HELLO WORLD")
        size = len(matrix)
        for row, column in ((0, 0), (0, size - 7), (size - 7, 0)):
            assert matrix[row][column] == 1
            assert matrix[row + 1][column + 1] == 0
            assert matrix[row + 3][column + 3] == 1

    def test_the_timing_patterns_alternate(self):
        matrix = qr.encode("HELLO WORLD")
        size = len(matrix)
        for index in range(8, size - 8):
            assert matrix[6][index] == (1 if index % 2 == 0 else 0)
            assert matrix[index][6] == (1 if index % 2 == 0 else 0)

    def test_the_dark_module_is_set(self):
        matrix = qr.encode("HELLO WORLD")
        assert matrix[len(matrix) - 8][8] == 1

    def test_encoding_is_deterministic(self):
        assert qr.encode("HELLO WORLD") == qr.encode("HELLO WORLD")

    def test_bigger_payloads_need_bigger_symbols(self):
        small = len(qr.encode("A"))
        large = len(qr.encode("x" * 100))
        assert large > small


class TestBounds:
    def test_an_empty_payload_is_refused(self):
        with pytest.raises(qr.QRError):
            qr.encode("")

    def test_a_non_string_is_refused(self):
        with pytest.raises(qr.QRError):
            qr.encode(None)

    def test_a_payload_beyond_version_10_is_refused(self):
        """Refusé clairement plutôt que rendu un symbole illisible."""
        with pytest.raises(qr.QRError):
            qr.encode("x" * 5000)

    def test_byte_mode_handles_what_alphanumeric_cannot(self):
        matrix = qr.encode("tcp://203.0.113.7:9000")   # minuscules et '/'
        assert len(matrix) >= 21


class TestSvg:
    def test_the_svg_is_well_formed(self):
        import xml.etree.ElementTree as ET
        ET.fromstring(qr.svg_for("HELLO WORLD"))

    def test_the_quiet_zone_is_included(self):
        """Sans zone de silence, un scanner ne trouve simplement pas le
        symbole."""
        matrix = qr.encode("HELLO WORLD")
        svg = qr.to_svg(matrix, scale=1, quiet=4)
        assert 'width="29"' in svg          # 21 modules + 4 de chaque côté

    def test_nothing_external_is_referenced(self):
        svg = qr.svg_for("HELLO WORLD")
        assert "http://www.w3.org/2000/svg" in svg     # namespace, pas un lien
        assert "<image" not in svg and "href" not in svg


# ── vérifications fortes, si l'outillage est là ──────────────────────────────

def _decode(matrix, scale=8, quiet=4):
    cv2 = pytest.importorskip("cv2")
    numpy = pytest.importorskip("numpy")
    size = len(matrix)
    total = (size + quiet * 2) * scale
    image = numpy.full((total, total), 255, dtype=numpy.uint8)
    for row in range(size):
        for column in range(size):
            if matrix[row][column]:
                y, x = (row + quiet) * scale, (column + quiet) * scale
                image[y:y + scale, x:x + scale] = 0
    data, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    return data


@pytest.mark.parametrize("text", [
    "HELLO WORLD",
    "A",
    "tcp://203.0.113.7:9000",
    "x" * 100,
])
def test_a_real_decoder_reads_it_back(text):
    assert _decode(qr.encode(text)) == text


def test_a_real_decoder_reads_a_join_ticket():
    text = _ticket_text()
    assert _decode(qr.encode(text)) == text


def test_the_svg_itself_decodes():
    """Le maillon que le reste ne couvre pas : ce sont les rectangles du SVG que
    la caméra voit, pas la matrice. On les relit pour vérifier qu'ils disent la
    même chose."""
    import re
    text = _ticket_text()
    scale, quiet = 4, 4
    svg = qr.svg_for(text, scale=scale, quiet=quiet)
    matrix = qr.encode(text)
    size = len(matrix)

    rebuilt = [[0] * size for _ in range(size)]
    for x, y in re.findall(r'<rect x="(\d+)" y="(\d+)" width="\d+" height="\d+" '
                           r'fill="#000000"/>', svg):
        column = int(x) // scale - quiet
        row = int(y) // scale - quiet
        rebuilt[row][column] = 1
    assert rebuilt == matrix
    assert _decode(rebuilt) == text


@pytest.mark.parametrize("text", ["HELLO WORLD", "NMESH JOIN TICKET 123"])
def test_identical_to_an_independent_encoder(text):
    """Même version, même niveau, même masque : les matrices doivent être
    identiques module par module."""
    qrcode = pytest.importorskip("qrcode")
    from qrcode.constants import ERROR_CORRECT_M, ERROR_CORRECT_L

    mine = qr.encode(text)
    mode = "alphanumeric" if qr._is_alphanumeric(text) else "byte"
    version, level = qr._pick_version(text, mode)
    constant = ERROR_CORRECT_M if level == "M" else ERROR_CORRECT_L
    for mask in range(8):
        reference = qrcode.QRCode(version=version, error_correction=constant,
                                  box_size=1, border=0, mask_pattern=mask)
        reference.add_data(text)
        reference.make(fit=False)
        matrix = [[1 if cell else 0 for cell in row]
                  for row in reference.get_matrix()]
        if matrix == mine:
            return
    pytest.fail(f"no mask of the reference encoder matches ours for {text!r}")
