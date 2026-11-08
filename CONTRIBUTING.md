# Contributing to Neutral Trust Infrastructure:

We welcome community contributions! Please read this guide before getting started.

---

## 0. Developer Certificate of Origin (DCO) — Required

**All commits MUST be signed off using `git commit -s` to comply with the Developer Certificate of Origin (DCO).**

Every commit in a pull request must contain a `Signed-off-by:` line with your real
name and email address, matching the commit author. The DCO is a lightweight
statement that you have the right to submit the contribution under the project's
open-source license. The full text is at
<https://developercertificate.org/>.

Add the sign-off automatically:

```bash
git commit -s -m "your commit message"
```

This appends a line such as:

```
Signed-off-by: Jane Doe <jane.doe@example.com>
```

If you forgot, amend the commit and force-push your branch:

```bash
git commit --amend -s
git push --force-with-lease
```

Pull requests whose commits lack a sign-off will fail the `DCO` check and cannot
be merged.

---

## 1. Contributor License Agreement (CLA)

All contributors must sign our Contributor License Agreement (CLA) before any code can be merged.

* When you open your first Pull Request (PR), an automated CLA bot will leave a comment on your PR prompting you to sign.
* **Your PR cannot be merged until the CLA check passes.**
* *Why this matters:* The CLA ensures you retain author credit while granting the project maintainer the legal rights required to manage, re-license, and protect the codebase as it evolves into a commercial platform.

---

## 2. How to Submit a Contribution

1. **Find or Open an Issue:** Check the project roadmap or existing issues before starting major work.
2. **Fork and Branch:** Create a feature branch off of `main` (e.g., `feature/vote-signing`).
3. **Run Tests Locally:** Ensure `cargo test` and `cargo build` pass cleanly before submitting.
4. **Submit a Pull Request:** Open a PR targeting the `main` branch with a clear title and description of your changes.
5. **Sign the CLA:** Follow the prompt provided by the CLA bot on your PR.

---

## 3. Contribution Standards

* **Keep PRs Scoped:** Submit small, focused PRs that solve a single problem rather than massive refactors.
* **Add Tests:** Any new feature or bug fix must include corresponding automated unit or integration tests.
* 
