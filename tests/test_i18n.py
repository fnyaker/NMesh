"""Every sentence reaches a person through one catalogue per language.

The catalogues are data a person can edit, so the checks are on the data: the
same keys everywhere, the same parameters in every translation, the plural
forms each language needs. The browser reads the same files, so its plural rule
and its parameter filling are held to the Python ones by running both.
"""
import json
import os
import random
import re
import shutil
import subprocess

import pytest

from src import config, i18n
from src.app_registry import AppHost, AppRegistry
from src.webassets import ui

NODE = shutil.which("node")
LOCALES = os.path.join(os.path.dirname(i18n.__file__), "locales")
PARAMS = re.compile(r"\{([a-z][a-z0-9_]*)\}")

# What each language must be able to say for a plural entry (CLDR categories
# for integers; "other" is always required).
REQUIRED_FORMS = {
    "en": {"one", "other"}, "de": {"one", "other"}, "fr": {"one", "other"},
    "zh": {"other"},
    "ru": {"one", "few", "many", "other"},
    "pl": {"one", "few", "many", "other"},
    "sk": {"one", "few", "other"},
}


def _raw(language):
    with open(os.path.join(LOCALES, language + ".json"), encoding="utf-8") as handle:
        return json.load(handle)


def _forms(value):
    return value if isinstance(value, dict) else {"other": value}


class TestTheLanguagesWeShip:
    def test_the_seven_languages(self):
        assert set(i18n.LANGUAGES) == {"en", "fr", "de", "ru", "zh", "pl", "sk"}

    def test_the_config_names_the_same_languages(self):
        assert tuple(config.LANGUAGES) == tuple(i18n.LANGUAGES)

    @pytest.mark.parametrize("language", i18n.LANGUAGES)
    def test_the_catalogue_is_the_shape_we_read(self, language):
        i18n._check(_raw(language))
        assert i18n.load(language) == _raw(language)

    @pytest.mark.parametrize("language", [l for l in i18n.LANGUAGES if l != "en"])
    def test_a_translation_has_exactly_the_keys_of_english(self, language):
        english, other = _raw("en"), _raw(language)
        assert sorted(other) == sorted(english), (
            sorted(set(english) ^ set(other)))

    @pytest.mark.parametrize("language", [l for l in i18n.LANGUAGES if l != "en"])
    def test_a_translation_keeps_the_parameters_of_english(self, language):
        english, other = _raw("en"), _raw(language)
        for key, value in english.items():
            wanted = set(PARAMS.findall(" ".join(_forms(value).values())))
            for form, text in _forms(other[key]).items():
                assert set(PARAMS.findall(text)) <= wanted, (language, key, form)
            # every form of a plural carries the count it is chosen by
            if isinstance(other[key], dict):
                for form, text in other[key].items():
                    assert "{count}" in text, (language, key, form)

    @pytest.mark.parametrize("language", i18n.LANGUAGES)
    def test_a_plural_entry_has_the_forms_its_language_uses(self, language):
        for key, value in _raw(language).items():
            if isinstance(value, dict):
                assert REQUIRED_FORMS[language] <= set(value), (language, key)

    @pytest.mark.parametrize("language", i18n.LANGUAGES)
    def test_no_value_is_empty(self, language):
        for key, value in _raw(language).items():
            for text in _forms(value).values():
                assert text.strip(), (language, key)

    def test_every_language_names_every_language_in_itself(self):
        for language in i18n.LANGUAGES:
            for code, name in i18n.NAMES.items():
                assert _raw(language)["language.name." + code] == name


class TestPlurals:
    @pytest.mark.parametrize("language,count,form", [
        ("en", 1, "one"), ("en", 0, "other"), ("en", 2, "other"),
        ("fr", 0, "one"), ("fr", 1, "one"), ("fr", 2, "other"),
        ("de", 1, "one"), ("de", 5, "other"),
        ("zh", 1, "other"), ("zh", 0, "other"),
        ("ru", 1, "one"), ("ru", 21, "one"), ("ru", 11, "many"),
        ("ru", 2, "few"), ("ru", 24, "few"), ("ru", 12, "many"), ("ru", 0, "many"),
        ("pl", 1, "one"), ("pl", 21, "many"), ("pl", 2, "few"),
        ("pl", 12, "many"), ("pl", 22, "few"), ("pl", 5, "many"),
        ("sk", 1, "one"), ("sk", 3, "few"), ("sk", 5, "other"), ("sk", 0, "other"),
        ("sk", 1.5, "many"),
    ])
    def test_the_form_of_a_count(self, language, count, form):
        assert i18n.plural_form(language, count) == form

    def test_a_count_that_is_not_a_number_is_other(self):
        for bad in (None, "x", [], {}, float("nan")):
            assert i18n.plural_form("ru", bad) == "other"

    @pytest.mark.parametrize("language", i18n.LANGUAGES)
    def test_every_catalogue_sentence_with_a_count_reads_right(self, language):
        for count in (0, 1, 2, 5, 11, 21, 22, 100):
            text = i18n.t("count.node", language, count=count)
            assert str(count) in text and "{" not in text

    @pytest.mark.skipif(NODE is None, reason="node is needed to ask Intl")
    @pytest.mark.parametrize("language", i18n.LANGUAGES)
    def test_the_browser_gives_the_same_form_for_a_whole_number(self, language):
        script = ("const r = new Intl.PluralRules(%r); const out = [];"
                  "for (let n = 0; n <= 300; n++) out.push(r.select(n));"
                  "console.log(JSON.stringify(out));" % language)
        result = subprocess.run([NODE, "-e", script], capture_output=True,
                                text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        browser = json.loads(result.stdout)
        assert browser == [i18n.plural_form(language, n) for n in range(301)]


class TestAsking:
    def test_a_sentence_in_the_language_asked(self):
        assert i18n.t("common.save", "fr") == "Enregistrer"
        assert i18n.t("common.save", "de") == "Speichern"

    def test_a_language_we_do_not_ship_is_english(self):
        assert i18n.t("common.save", "xx") == "Save"

    def test_a_missing_key_shows_as_itself(self):
        assert i18n.t("no.such.key", "fr") == "no.such.key"

    def test_a_key_missing_in_a_translation_falls_back_to_english(self, tmp_path):
        (tmp_path / "en.json").write_text('{"a.b": "hello"}', encoding="utf-8")
        (tmp_path / "fr.json").write_text("{}", encoding="utf-8")
        english = i18n.load("en", str(tmp_path))
        assert english == {"a.b": "hello"} and i18n.load("fr", str(tmp_path)) == {}

    def test_parameters_are_filled_and_an_unknown_one_stays_written(self):
        assert i18n._fill("{count} x {other}", {"count": 3}) == "3 x {other}"

    def test_a_catalogue_cannot_reach_into_what_it_is_given(self):
        class Secret:
            token = "hunter2"
        for template in ("{x.token}", "{x!r}", "{0}", "{x[0]}", "{{x}}"):
            assert "hunter2" not in i18n._fill(template, {"x": Secret()})

    def test_a_plural_chosen_by_count(self):
        assert i18n.t("count.node", "ru", count=1) == "1 узел"
        assert i18n.t("count.node", "ru", count=3) == "3 узла"
        assert i18n.t("count.node", "ru", count=7) == "7 узлов"
        assert i18n.t("count.node", "zh", count=7) == "7 个节点"

    def test_a_plural_without_a_count_is_other(self):
        assert i18n.t("count.node", "en") == "{count} nodes"


class TestACatalogueThatIsWrong:
    @pytest.mark.parametrize("body", [
        "not json", "[]", '"x"', '{"Bad Key": "x"}', '{"nodots": "x"}',
        '{"a.b": 3}', '{"a.b": {"one": "x"}}', '{"a.b": {"other": "x", "weird": "y"}}',
        '{"a.b": "' + "x" * 5000 + '"}',
    ])
    def test_it_is_refused_whole_and_costs_only_its_language(self, tmp_path, body):
        (tmp_path / "fr.json").write_text(body, encoding="utf-8")
        assert i18n.load("fr", str(tmp_path)) == {}

    def test_a_file_that_is_not_there(self, tmp_path):
        assert i18n.load("fr", str(tmp_path)) == {}

    def test_a_language_that_is_not_one_of_ours_reads_nothing(self, tmp_path):
        assert i18n.load("../x", str(tmp_path)) == {}


class TestChoosing:
    def test_the_operators_choice_wins(self):
        assert i18n.effective("de", "fr-FR,fr;q=0.9") == "de"

    def test_without_one_the_browser_picks(self):
        assert i18n.effective("", "fr-FR,fr;q=0.9,en;q=0.5") == "fr"
        assert i18n.effective(None, "zh-CN") == "zh"

    def test_a_weight_orders_the_choice(self):
        assert i18n.negotiate("en;q=0.3, sk;q=0.9, de;q=0.5") == "sk"

    def test_q_zero_is_a_refusal(self):
        assert i18n.negotiate("fr;q=0, de;q=0.2") == "de"

    def test_nothing_we_ship_is_english(self):
        assert i18n.effective("", "ja,ko;q=0.9") == "en"
        assert i18n.effective("", None) == "en"
        assert i18n.effective("klingon", "") == "en"

    def test_a_hostile_header_never_raises(self):
        rng = random.Random(7)
        alphabet = "abcdefghijklmnopqrstuvwxyz-;=,.q0123456789 \x00‮{}"
        for _ in range(2000):
            header = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 900)))
            result = i18n.effective("", header)
            assert result in i18n.NAMES
        for bad in (b"fr", 3, [], {}):
            assert i18n.negotiate(bad) is None

    def test_a_flood_of_entries_is_read_to_a_bound(self):
        header = ",".join(["xx"] * 100000) + ",fr"
        assert i18n.negotiate(header) is None

    def test_the_bundle_is_the_language_laid_over_english(self):
        merged = i18n.bundle("pl")
        assert set(merged) == set(i18n.load("en"))
        assert merged["common.save"] == "Zapisz"


class TestTheSetting:
    def test_it_takes_a_shipped_language_or_nothing(self):
        parser = config.SETTINGS["language"][0]
        assert parser("de") == "de" and parser(" FR ") == "fr" and parser("") == ""
        for bad in ("xx", "english", "fr-FR", "../fr"):
            with pytest.raises(config.ConfigError):
                parser(bad)

    def test_the_console_is_offered_a_choice(self):
        row = {r["name"]: r for r in config.public(config.defaults())}["language"]
        assert row["kind"] == "choice"
        assert row["choices"] == [""] + list(i18n.LANGUAGES)
        assert row["live"] is True and row["editable"] is True

    def test_it_is_read_back_from_the_file(self, tmp_path):
        path = str(tmp_path / "nmesh.conf")
        assert config.language(path) == ""
        values = config.defaults()
        values["language"] = "ru"
        config.save(path, values)
        assert config.language(path) == "ru"
        assert config.language(None) == ""

    def test_a_bad_value_in_the_file_is_no_language(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        path.write_text("language = klingon\n", encoding="utf-8")
        assert config.language(str(path)) == ""


class TestWhatTheAppsAreHanded:
    class _App:
        def __init__(self):
            self.heard = []

        async def start(self):
            pass

        async def stop(self):
            pass

        def set_language(self, code):
            self.heard.append(code)

    def _host(self, language, tmp_path):
        registry = AppRegistry(str(tmp_path))
        return AppHost(registry, language=language)

    def test_the_host_answers_the_choice(self, tmp_path):
        assert self._host(lambda: "de", tmp_path).language == "de"

    def test_without_a_source_it_follows_the_browser(self, tmp_path):
        assert self._host(None, tmp_path).language == ""

    def test_a_source_that_fails_is_no_language(self, tmp_path):
        def broken():
            raise RuntimeError("x")
        assert self._host(broken, tmp_path).language == ""
        assert self._host(lambda: 7, tmp_path).language == ""

    def test_a_running_app_hears_a_change_and_a_failing_one_costs_only_itself(
            self, tmp_path):
        host = self._host(lambda: "pl", tmp_path)
        good, bad = self._App(), self._App()

        def refuse(code):
            raise RuntimeError("no")
        bad.set_language = refuse
        host._running["good"] = (good, None)
        host._running["bad"] = (bad, None)
        host._running["bridge"] = (object(), good)
        host.set_language("sk")
        assert good.heard == ["sk", "sk"]

    async def test_an_app_is_told_the_language_when_it_starts(self, tmp_path):
        registry = AppRegistry(str(tmp_path))
        host = AppHost(registry, language=lambda: "fr")
        app = self._App()

        async def factory():
            return app, None
        name = registry.overview(set())[0]["id"]
        host.register(name, factory)
        registry.set_installed(name, True)
        registry.set_enabled(name, True)
        await host.apply()
        assert app.heard == ["fr"]


@pytest.mark.skipif(NODE is None, reason="node is needed to run the page script")
class TestThePageScript:
    @staticmethod
    def _run(lang, strings, body):
        start = ui.JS.index("// ---- language")
        end = ui.JS.index("// ---- icons")
        script = (
            "const NMESH_LANG = %s; const NMESH_I18N = %s;"
            "const document = {documentElement: {}, querySelectorAll: () => []};"
            "%s\n%s" % (json.dumps(lang), json.dumps(strings),
                        ui.JS[start:end], body))
        result = subprocess.run([NODE, "-e", script], capture_output=True,
                                text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    def test_it_speaks_the_catalogue(self):
        bundle = i18n.bundle("ru")
        out = self._run("ru", bundle, 'console.log(t("count.node", {count: 3}) + "|" '
                        '+ t("common.save") + "|" + document.documentElement.lang)')
        assert out == "3 узла|Сохранить|ru"

    def test_a_key_nobody_defined_shows_as_itself(self):
        assert self._run("en", {}, 'console.log(t("a.b"))') == "a.b"

    def test_a_parameter_is_filled_and_an_unknown_one_stays(self):
        out = self._run("en", {"x.y": "{a} and {b}"},
                        'console.log(t("x.y", {a: 1}))')
        assert out == "1 and {b}"

    def test_a_catalogue_cannot_inject_markup_through_a_parameter_name(self):
        out = self._run("en", {"x.y": "{__proto__} {constructor}"},
                        'console.log(t("x.y", {}))')
        assert out == "{__proto__} {constructor}"


class TestTheConsoleServesIt:
    def test_every_page_loads_the_script_after_the_theme(self):
        from src import webassets
        for html in (webassets.INDEX_HTML, webassets.CHAT_HTML, webassets.FLEET_HTML,
                     webassets.NODE_HTML, webassets.PKG_HTML, webassets.TERM_HTML):
            assert html.index('<script src="/theme.js">') < html.index(
                '<script src="/i18n.js">')


class TestTheConsoleSpeaks:
    @staticmethod
    async def _script(tmp_path, setting, header=None):
        import asyncio
        from tests.test_webconsole import _make_console, _request
        path = str(tmp_path / "nmesh.conf")
        values = config.defaults()
        values["language"] = setting
        config.save(path, values)
        node, console = await _make_console(config_path=path)
        try:
            headers = {"Accept-Language": header} if header else None
            status, response, payload, _ = await asyncio.to_thread(
                _request, console, "GET", "/i18n.js", None, None, None, False,
                None, headers)
            return status, response, payload.decode("utf-8")
        finally:
            console.stop()
            await node.stop()

    async def test_it_is_public_and_never_cached(self, tmp_path):
        status, headers, text = await self._script(tmp_path, "de")
        assert status == 200 and headers["cache-control"] == "no-store"
        assert text.startswith('window.NMESH_LANG="de";window.NMESH_I18N={')
        assert "Speichern" in text

    async def test_the_operators_choice_beats_the_browser(self, tmp_path):
        _, _, text = await self._script(tmp_path, "sk", "fr-FR,fr;q=0.9")
        assert 'NMESH_LANG="sk"' in text

    async def test_without_a_choice_the_browser_decides(self, tmp_path):
        _, _, text = await self._script(tmp_path, "", "pl-PL,pl;q=0.9,en;q=0.4")
        assert 'NMESH_LANG="pl"' in text

    async def test_with_neither_it_is_english(self, tmp_path):
        _, _, text = await self._script(tmp_path, "", "ja")
        assert 'NMESH_LANG="en"' in text


class TestEveryKeyAPageAsksForIsDefined:
    """`t("x.y")` shows `x.y` itself when nobody defined it — on purpose, so a gap
    is visible. It should be visible here, in a test, and not to a person."""

    @staticmethod
    def _asked(*sources):
        keys = set()
        for text in sources:
            keys |= set(re.findall(r'data-i18n="([^"]+)"', text))
            for pairs in re.findall(r'data-i18n-attr="([^"]+)"', text):
                keys |= {pair.split(":", 1)[1] for pair in pairs.split(";")}
            keys |= set(re.findall(r'\bt\("([a-z][a-z0-9_.]*[a-z0-9_])"', text))
            # `t(flag ? "a.b" : "a.c")`: both arms are asked for.
            for arms in re.findall(r'\bt\(\w+(?: \|\| \w+)? \? "([^"]+)" : "([^"]+)"', text):
                keys |= set(arms)
        return keys

    @pytest.mark.parametrize("language", sorted(REQUIRED_FORMS))
    def test_chat_and_contacts_say_everything_in_every_language(self, language):
        from src.webassets import chat, contacts
        asked = self._asked(chat.CHAT_HTML, chat.CHAT_PAGE_JS,
                            contacts.CONTACTS_HTML, contacts.CONTACTS_PAGE_JS)
        # What a page builds from a code (`contacts.err.<why>`, `.color.<name>`)
        # is asked for by prefix; each code the node can send is listed here.
        for why in ("no_book", "read_only", "no_contact", "empty", "full", "bad_node",
                    "not_owner", "self", "gone", "permission"):
            asked.add("contacts.err." + why)
        for color in ("blue", "green", "teal", "amber", "red", "purple", "pink", "gray"):
            asked.add("contacts.color." + color)
        defined = _raw(language)
        missing = sorted(key for key in asked if key not in defined)
        assert not missing, missing

    def test_the_node_cannot_send_a_refusal_the_page_has_no_words_for(self):
        from src.apps import contacts_web
        for why in contacts_web._CHANGES:
            assert "contacts.err." + why in _raw("en"), why
