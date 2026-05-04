from privacy_review_agent import git_diff


def test_changed_lines_skips_deletion_only_hunks(monkeypatch):
    diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -10,1 +10,0 @@
-old_line
"""
    monkeypatch.setattr(git_diff, "_run_git", lambda _: diff)
    assert git_diff.changed_lines("base", "head") == {"a.py": set()}


def test_changed_lines_tracks_added_line_ranges(monkeypatch):
    diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -2,0 +3,3 @@
+line_one
+line_two
+line_three
"""
    monkeypatch.setattr(git_diff, "_run_git", lambda _: diff)
    assert git_diff.changed_lines("base", "head") == {"a.py": {3, 4, 5}}
