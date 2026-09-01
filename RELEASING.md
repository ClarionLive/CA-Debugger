# Releasing CA Debugger

CA Debugger is listed in the [Clarion Addin Registry](https://github.com/msarson/clarion-addin-registry)
as a **`setupAddins`** entry, in [ClarionLive/clarion-addins](https://github.com/ClarionLive/clarion-addins).

## The short version

**Publishing the GitHub release *is* the publication. There is nothing to update anywhere else.**

A `setupAddins` entry carries no version and no download URLs. Addin Finder resolves the latest
release of `githubRepo` through the GitHub API at runtime and caches it for 6 hours, so a new release
reaches users within 6 hours of them opening the pad. The installer's filename changes every release
and that is fine — the asset URL is resolved, never pinned.

**Do not edit `addins.json` for a release.** It has no field that a release changes. (That file only
needs editing to add or retire an addin, and even then it needs no pull request against the registry
and nobody's approval — that is what being a listed publisher means.)

## The four things that must be true

### 1. The manifest version equals the tag

`ClarionDebugger.addin`'s `<Identity version>` must equal the release tag with any leading `v`
removed. Addin Finder compares them component-wise and reads a *missing* component as `0`, so `1.2`
and `1.2.0` are equal — and nothing else is.

Get this wrong and the pad reads **"Update available" forever**. Reinstalling cannot clear it, because
the freshly-installed manifest keeps reasserting the same wrong number. This is not hypothetical:
**v1.1.0 shipped exactly that way**, with a manifest still declaring `1.0.0`, and every install of it
was stuck until v1.1.1.

Two guards enforce it, and neither should be removed:

- `CheckAddinVersion` in `src/ClarionDebugger.Addin/ClarionDebugger.Addin.csproj` — fails the build
  when `<Version>` and the manifest disagree. Uses `XmlPeek` rather than a regex (the manifest's own
  quotes and angle brackets break MSBuild property expansion) and is deliberately **not** gated on
  `Configuration == Release`, because we ship Debug builds.
- The staged-manifest gate in `installer/build-installer.ps1` — checks the manifests that actually
  reached `staging\`, which is the artifact rather than the source. This is the gate v1.1.0 lacked.

### 2. The new version is numerically *greater* than anything shipped before

Not merely different. Addin Finder only ever moves a recorded version **forward**
(`InstalledAddinStore.Reconcile`), so a number lower than one a user already has is silently refused
and they stay stuck on the old one.

Compare against the highest version ever shipped **in a manifest**, which is not necessarily the last
tag. (The sibling ClarionAssistant repo had shipped `5.8.1137` under a `v5.8.1` tag, which is why its
next release had to be `5.9.0` and not `5.8.2`.)

### 3. `id` still matches the install folder

The registry entry's `id` is **`ClarionDebugger`** — the folder the installer creates under
`accessory\addins`. It is *not* the repository name. If the installer's target folder ever changes,
the registry entry must change with it, or the addin silently never shows as installed and never
reports a version.

### 4. The build is not a `-NoBuild` build

`build-installer.ps1` builds once per Clarion version into the *same* `bin\Debug` and stages after
each pass. Under `-NoBuild` nothing rebuilds, so all three staging folders receive whichever single
DLL happens to be there — C10 and C11 would ship a C12-linked DLL, silently. **The version gates
cannot catch this**: every copy carries the correct version and only the binding differs.

## The build number, and the third gate

Since v1.1.1 the pad caption carries a build number — the pad reads **"CA Debugger v1.1.1.136"**:
`Major.Minor.Patch` plus a git commit count. The same value appears in `FileVersion` and
`InformationalVersion`.

**It is derived, not authored.** Nobody bumps it; `ComputeBuildNumber` reads
`git rev-list --count HEAD`. Do not hand-edit it, and **never promote it into `<Identity version>`
or the release tag** — a build number in the compared version is exactly the shape that made v1.1.0
unfixable.

It is also monotonic only along a *linear* history: a feature branch can carry a higher count than
main, and a squash-merge can land main on a lower count than a dev build already produced. That is
harmless where the number lives, and would not be if it ever reached a compared version.

**A third gate can fail your release build, and its message is unlike the other two.**
`build-installer.ps1` compares each staged pad caption against that staged DLL's `FileVersion` and
throws when they disagree. It means the manifest was not restamped for this build. The fix is a
clean rebuild — never editing the caption by hand.

It guards a **different axis** from the version gates: `<Identity version>` can be perfectly correct
while the caption is a build behind. That was observed during development — `FileVersion 1.1.1.132`
against a caption reading `v1.1.1.131`, with Identity right the whole time.

**It does not catch a `-NoBuild` build.** Under `-NoBuild` the staged manifest and the staged DLL
both come from the same stale `bin\Debug`, so the caption and `FileVersion` agree and the gate
passes. Point 4 above stands exactly as written: `-NoBuild` is caught by nothing.

## The sequence

```powershell
# 1. Bump BOTH, to the same number:
#      src\ClarionDebugger.Addin\ClarionDebugger.Addin.csproj   <Version>
#      src\ClarionDebugger.Addin\ClarionDebugger.addin          <Identity version>
#    (the build will refuse if they disagree)

# 2. Write the CHANGELOG entry, crediting contributors by handle.

# 3. Build + sign. NOT -NoBuild.
cd installer
.\build-installer.ps1 -Sign

# 4. Tag to match, and publish with the installer attached.
git tag -a v<version> -m "CA Debugger v<version>"
git push origin main --follow-tags
gh release create v<version> installer\output\CA-Debugger-<version>-Setup.exe `
  --title "CA Debugger v<version>" --latest
```

Then stop. Nothing else needs doing — no registry edit, no pull request, no waiting.

## Checking it worked

```powershell
# What Addin Finder will read as the published version:
gh api repos/ClarionLive/CA-Debugger/releases/latest --jq '.tag_name'
```

That, minus its leading `v`, must equal the `<Identity version>` inside the shipped installer. The
decisive check is the pad itself: open Addin Finder in the IDE and confirm CA Debugger reads
**Installed** rather than *Update available*.
