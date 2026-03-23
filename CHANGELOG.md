# Changelog

All notable changes to DarkShell will be documented in this file.

## [1.0.0] - 2026-03-23

### Bug Fixes

- Remediate 5 critical findings from adversarial code review
- Remediate darkshell-observe High+Medium findings
- Remediate darkshell-mcp High+Medium findings
- Remediate blueprint+CLI High+Medium findings
- Remediate all 21 LOW findings from adversarial review
- Use ephemeral port in sandbox_create_keeps_sandbox_with_forwarding test

### CI/CD

- Add complete CI/CD pipeline for DarkShell
- Add doc-only skip workflow and release sync-main

### Documentation

- *(providers)* Add Groq to the supported providers table (#518)
- Add VSDD pipeline artifacts (brief, PRD, architecture, stories)
- Replace upstream README with DarkShell-specific documentation

### Features

- *(ds-001)* Rename binary from openshell to darkshell
- *(ds-014)* Add darkshell-blueprint crate with schema validation
- *(ds-003)* Support multiple --upload on sandbox create
- *(ds-007)* Add sandbox exec with SSH ControlMaster
- *(ds-008)* Implement MCP bridge daemon
- *(ds-004)* Add progress bar to upload and download
- *(ds-016)* Add sandbox watch with live event streaming
- *(ds-002)* Add rsync delta upload with tar fallback
- *(ds-005)* Add download --include/--exclude filtering
- *(ds-011)* Support in-sandbox stdio MCP servers
- *(ds-010)* Add MCP tool-level policy at bridge layer
- *(ds-013)* Add MCP tool call logging at bridge layer
- *(ds-015)* Implement blueprint-based sandbox creation
- *(ds-009)* Add MCP CLI management (add/list/remove)
- *(ds-006)* Add upload --dry-run preview
- *(ds-020)* Add inference request/response logging hook

### Miscellaneous

- Merge upstream NVIDIA/OpenShell v0.0.13 into DarkShell
- Merge DS-003 multi-upload into develop
- Merge DS-007 exec command into develop
- Merge DS-008 MCP bridge daemon into develop
- Regenerate Cargo.lock after DS-008 merge
- Merge DS-004 progress bars into develop
- Merge DS-004 progress bars and DS-016 sandbox watch into develop
- Merge DS-002 rsync upload into develop
- Merge DS-005 download filtering into develop
- Merge DS-011 in-sandbox MCP into develop
- Mark 16 v1.0 stories as done
- Update CODEOWNERS to @drbothen

### Refactor

- Move DarkShell CLI tests to tests/darkshell/ subdirectory

### Testing

- Add integration tests for blueprint orchestration + in-sandbox MCP (WF-4, WF-6)
- Add integration tests for upload, exec, and MCP CLI workflows (WF-1, WF-2)
- Add integration tests for MCP bridge + observe workflows (WF-3, WF-5)

## [0.0.13] - 2026-03-21

### Bug Fixes

- *(docker)* Propagate OPENSHELL_IMAGE_TAG to cross-compile Dockerfiles (#530)

### CI/CD

- *(release)* Restrict auto-tag to weekdays only (#507)

### Documentation

- *(ollama)* Update ollama tutorial and references to match latest (#511)
- *(ollama)* Fix references to renamed tutorial file (#513)

### Features

- *(providers)* Add GitHub Copilot CLI agent provider (#476)
- *(gpu)* Disable NFD/GFD and remove nodeAffinity from device plugin chart (#497)
- *(ocsf)* Create openshell-ocsf crate — standalone OCSF event types, formatters, and tracing layers (#489)
- *(settings)* Gateway-to-sandbox runtime settings channel (#474)

### Refactor

- *(proto)* Rename UpdateSettings to UpdateConfig for consistency with read path (#515)
- *(sandbox)* Remove unused pod_template field from CreateSandbox RPC (#522)

## [0.0.12] - 2026-03-20

### Bug Fixes

- *(bootstrap)* Surface diagnostics for K8s namespace not ready failures (#466)
- *(sandbox)* Rotate openshell.log daily, keep 3 files (#431)
- *(e2e)* Update log-reading helpers for rolling file appender (#480) (#481)
- *(router)* Increase inference validation token budget (#432)
- *(gateway)* Allow first live network policy update (#493)
- *(docker)* Set migrations dir permissions to 755 on COPY (#475)

### Documentation

- Add guidance for OpenAI-compatible cloud providers (#458)

## [0.0.11] - 2026-03-19

### Bug Fixes

- *(ci)* Use published install script in release workflows (#416)
- *(deploy)* Remove duplicate glob pattern in manifest cleanup loop (#428)
- *(ci)* Check author_association before API calls in vouch gate (#442)
- *(ci)* Fetch author_association via REST API instead of webhook payload (#444)
- *(ci)* Pass wheel filenames as job output instead of re-downloading (#418)
- *(ci)* Use ORG_READ_TOKEN for org membership check in vouch gate (#445)
- *(ci)* Split vouch gate into two steps with separate tokens (#446)
- *(cli)* Suppress browser popup during auth via OPENSHELL_NO_BROWSER env var (#419)
- *(ci)* Use env context instead of secrets in step-level if condition (#452)
- *(ci)* Simplify dev release install instructions to use install.sh (#453)
- *(bootstrap)* Auto-cleanup Docker resources on failed gateway deploy (#464)

### Miscellaneous

- *(repo)* Migrate github label taxonomy (#454)

### Refactor

- *(build)* Unify image build graph for cache reuse (#390)

## [0.0.10] - 2026-03-18

### Bug Fixes

- *(server)* Add startup probe for gateway boot (#417)

## [0.0.9] - 2026-03-17

### Bug Fixes

- *(verification)* Send content type (#382)
- *(ci)* Skip auto-tag when no new commits since latest tag (#399)
- *(docs)* Resolve Pygments console lexer error in LM Studio tutorial (#402)
- *(installer)* Remove duplicate app name in install output (#408)

### Documentation

- *(inference)* Add LM Studio guide (#386)
- *(ollama)* Add ollama to community sandboxes catalog and supported agents (#383)

### Refactor

- Simplify install.sh to print PATH guidance (#403)

## [0.0.8] - 2026-03-17

### Bug Fixes

- *(ci)* Use github-script for wheel pruning instead of gh CLI (#354)
- Security hardening from aardvark/codex scanner findings (#352)
- *(bootstrap)* Use host cgroup namespace for gateway container (#329)
- *(bootstrap)* Support cgroup v1 hosts by disabling kubelet failCgroupV1 check (#360)
- *(ci)* Add actions:write permission to release-auto-tag workflow (#361)
- *(cli)* Use --name flag in gateway destroy help messages (#368)
- *(e2e)* Replace Docker Hub images in E2E tests to avoid rate limits (#369)
- Use dedicated vouched branch to avoid branch protection (#379)
- *(ci)* Skip remote sccache config for fork PRs (#388)

### CI/CD

- *(release)* Enable scheduled nightly release auto-tag (#384)

### Documentation

- Unify install command in landing page, change docs skill name, update contributing guides (#355)
- Add docs badge to readme (#370)

### Features

- *(policy)* Support host wildcards and multi-port endpoints (#366)

### Miscellaneous

- Update readme (#356)
- Update readme (#357)
- Add vouch system for first-time contributors (#375)
- Pin mitchellh/vouch actions to SHA (#377)
- Replace mitchellh/vouch with hand-rolled workflows (#378)

### Performance

- *(docker)* Move version ARG below cached layers to fix cache invalidation (#385)

### Refactor

- *(proxy)* Distinguish CONNECT_L7 from CONNECT in policy logs (#365)

## [0.0.6] - 2026-03-16

### Bug Fixes

- *(ci)* Run wheel pruning before moving devel tag (#334)

### Documentation

- *(readme)* Improve clarity, structure, and contributor discoverability (#336)
- Add debug-inference skill, Ollama tutorial, and remove stale inference policy references (#353)

### Features

- *(sandbox)* Log connection attempts that bypass proxy path (#326)

### Miscellaneous

- Pre-release readiness (#313)

## [0.0.5] - 2026-03-16

### Bug Fixes

- *(ci)* Trigger release-tag workflow via workflow_dispatch from auto-tag (#315)
- *(cli)* Check port availability before starting SSH forward (#309)
- *(router)* Stop dropping client-sent default headers like anthropic-version (#320)
- *(ci)* Use BuildKit secrets instead of build-arg for GITHUB_TOKEN (#327)
- *(core)* Harden file permissions for user config directory (#328)
- *(ci)* Remove legacy wheel publishing machinery (#331)
- *(ci)* Prune stale devel wheel assets (#332)

### CI/CD

- *(release)* Use native GitHub release notes and add e2e gate (#318)
- *(release)* Gate python wheels on e2e for tagged releases (#319)
- *(release)* Trigger GitLab wheel publish workflows (#323)
- *(canary)* Add two-step gateway start + sandbox create canary test (#325)

### Documentation

- Few more bits of docs improvement (#324)
- Simplify quickstart install, reorder sections, and clean up sandbox docs (#330)

### Features

- *(bootstrap)* Add Docker preflight check before gateway startup (#321)
- *(inference)* Verify endpoints before saving routes (#291)

### Miscellaneous

- Remove remaining navigator and nemoclaw references (#279)
- *(python)* Refine package metadata (#317)

### Testing

- *(e2e)* Run host alias checks from docker (#314)

## [0.0.4] - 2026-03-15

### Bug Fixes

- *(canary)* Use curl instead of gh CLI for release download (#299)
- *(cli)* Show startup feedback for foreground forwards (#296)

### CI/CD

- *(release)* Add canary triggered after release workflow (#298)
- *(release)* Add auto-tag workflow for patch version bumping (#307)
- Various CI improvements (#312)

### Documentation

- Add dedicated gateway docs, network policy tutorial, and license page (#294)
- Improve the docs more (#308)

### Features

- *(bootstrap)* Restore per-gateway Docker bridge networks (#303)
- *(cli)* Add no-verify inference flag (#302)
- *(sandbox)* Inject host gateway hostAliases into sandbox pods (#306)

### Miscellaneous

- Establish agent-first development ethos across project (#293)
- Add docs contributing guides and skills (#301)
- Derive build version from git tags for all components (#305)
- *(ci)* Upload Python wheels to release assets (#300)

## [0.0.3] - 2026-03-14

### CI/CD

- *(release)* Pin OPENSHELL_IMAGE_TAG to version for tagged releases (#297)

## [0.0.1] - 2026-03-14

### Bug Fixes

- *(sandbox)* Flaky status updates
- *(server)* Cleanup server multiplexing, tls
- *(sandbox)* Dynamically create and chown read_write directories
- *(sandbox)* Add network namespace isolation for proxy mode
- *(cluster)* Use iptables DNS proxy instead of host gateway for k3s DNS
- *(docs)* Update quickstart command
- *(ci)* Install docker buildx plugin for multi-arch image builds
- *(ci)* Create multi-platform buildx builder for ECR publish mode
- *(ci)* Create docker context for TLS-enabled DinD before buildx
- *(ci)* Unset TLS env vars before buildx to avoid context conflict
- *(ci)* Publish_ecr_images correctly publishes images (!15)
- *(cluster)* Preserve gateway TLS settings during cluster deploy
- *(sandbox)* Enforce network namespace and proxy policy in SSH sessions (!17)
- *(ci)* Install cargo:cargo-edit on the CI image, add file that got missed
- *(ci)* Make the multiplatform wheel build work in CI
- *(cli)* Use raw cluster name for remote kubeconfig path lookup (!25)
- *(cluster)* Remove stale image on destroy and verify architecture after pull
- *(security)* Reject CONNECT to internal IPs (SSRF defense-in-depth) (!37)
- *(ci)* Resolve sandbox Dockerfile path in multiarch publish script
- *(ci)* Update publish job to see all tags
- *(sandbox)* Prevent 30s stalls in HTTP proxy response relay (!44)
- *(sandbox)* Avoid repeated TOFU rehashing for unchanged binaries (!47)
- *(sandbox)* Fail closed when proxy netns setup fails (!50)
- *(providers)* Prevent home path escape in expand_home (!54)
- *(cli)* Use cluster URL port for SSH gateway resolution (!57)
- *(router)* Replace model ID in request body with route-configured model (!56)
- *(sandbox)* Emit structured CONNECT deny log for inference interception failures (!60)
- *(sandbox)* Add HTTP/2 keep-alive and reconnect loop for log push (!61)
- *(logs)* Reduce log noise and add reconnect observability (!62)
- *(providers)* Use name instead of type on lookup (#46)
- Inference routing improvements (#56)
- *(cli)* Pass cluster name to ssh-proxy child process for correct TLS path resolution (#52)
- *(ci,publish)* Harden publish flow and cache nemoclaw wheel builds (#55)
- *(cluster)* Fully release resources on destroy to prevent port conflicts (#64)
- *(sandbox)* Eliminate SSH transport race causing flaky E2E tests (#69)
- *(ci)* Pin Python to 3.12.12 to avoid broken 3.12.13 source build (#74)
- *(ci)* Harden cargo build retry by wiping target dir and disabling sccache (#77)
- *(proxy)* Return 403 for non-CONNECT requests, add deny logging, and revise error messages (#79)
- *(cli)* Add path hints for file-valued flags (#86)
- *(sandbox)* Fix data corruption in sync --down and hang in sync --up (#93)
- *(ci)* Replace deleted gsactions/dco-check with contributor-assistant (#98)
- *(security)* Harden sandbox SSH with mandatory HMAC secret, NetworkPolicy, and nonce replay detection (#127)
- *(sandbox)* Remove control plane bypass from proxy (#128)
- *(sandbox)* Verify effective UID/GID after privilege drop (#132)
- *(cluster)* Add openssl package to cluster image (#137)
- *(server)* Prevent unbounded bus entry growth for sandbox IDs (#138)
- *(cluster)* Replace openssl with /dev/urandom in cluster image (#139)
- *(server)* Clamp list RPC page limit to prevent unbounded queries (#140)
- *(docker)* Remediate container scan vulnerabilities across CI, cluster, and sandbox images (#144)
- *(server)* Add field-level size limits to sandbox and provider creation (#145)
- *(build)* Propagate packaged version through cluster artifacts (#164)
- *(ci)* Standardize safe tag fetches (#165)
- *(ci)* Drop unnecessary pipefail in docker build workflow (#166)
- *(ci)* Use docker-safe publish image tags (#169)
- *(cli)* Scope git-aware sandbox uploads to requested path (#171)
- *(sandbox)* Fix create ordering race, dual-registry credentials, and policy identity clearing (#176)
- *(security)* Add SSH session token expiry, connection limits, and lifecycle cleanup (#182)
- *(sandbox)* Treat IPv6 ULA addresses as internal (#173)
- *(sandbox)* Improve inference route refresh with conditional fetch and configurable interval (#185)
- *(containers)* Remediate high-severity container vulnerabilities and remove openclaw (#191)
- *(tui)* Use correct ssh-proxy CLI args in shell connect and exec (#193)
- *(docker)* Remove unsupported npm dedupe -g command (#194)
- *(server)* Merge provider credentials/config on update instead of replacing (#202)
- *(bootstrap)* Update hardcoded navigator namespace refs to openshell (#212)
- Switch community sandbox registry to GHCR and align TLS paths (#218)
- *(cli)* Improve sandbox provisioning progress indicator (#221)
- *(cluster)* Skip DNS probe for IP-literal registry hosts (#229)
- *(policy)* Enforce run_as_user/run_as_group must be 'sandbox' (#230)
- *(cli)* Improve completion coverage and gateway selection (#241)
- *(cluster)* Add missing k9s build stage to Dockerfile.cluster (#254)
- *(cluster)* Run helm/kubectl inside container via docker exec (#255)
- *(proxy)* Stream inference responses instead of buffering entire body (#261)
- *(cli)* Add --no-keep for ephemeral sandbox create cleanup (#258)
- *(sandbox)* Opt Node clients into proxy env support (#269)
- *(install)* Use gh CLI for release downloads instead of HTTP (#285)
- *(bootstrap)* Detect missing sandbox supervisor binary during gateway health check (#281)
- *(sandbox)* Bypass proxy for localhost traffic (#290)
- *(cli)* Use line-based stdin read for gateway recreate prompt (#292)

### Build

- Add publishing for docker images and python wheel

### CI/CD

- Add GitHub Actions CI workflow with lint, test, and image build (#1)
- Add publish workflow and refactor e2e into reusable workflow (#53)
- Fix docs-build publish job and rename snapshot release to devel (#121)
- *(docs)* Disable publish job until GitHub Pages is configured (#122)
- Rename GHCR image paths from nv-agent-env to nemoclaw (#126)
- *(docs)* Finish setting up PR doc preview workflow (#160)
- Remove sandbox docker build from publish and e2e workflows (#275)
- Speed up E2E pipeline by running on arm64 runners and skipping redundant cluster rebuild (#278)

### Documentation

- Initialize DarkShell with kickstart, CLAUDE.md, and rules
- Add P8-P14 enhancements for production and development workflows
- Add SOUL.md adapted from Axiathon for DarkShell's domain
- Add Phase 0 fork + rename + verify build instructions to KICKSTART
- *(contributing)* Add kubernetes development instructions
- Add mise shell examples and document read_write auto-creation
- *(sandbox)* Document network namespace isolation
- *(readme)* Rewrite quickstart, fix macOS build scripts (!32)
- *(readme)* Add cluster deploy, upgrading, and sandbox tooling sections (#66)
- Add system architecture diagram and update arch-doc-writer agent (#72)
- Setup initial `docs/` infrastructure and scaffolding (#94)
- Reset CONTRIBUTING.md and add mise run docs task (#119)
- Consolidate information architecture and author content (#124)
- Simplified the sandbox docs (#186)
- Restructure and polish safety and policy section (#189)
- *(inference)* Clarify local inference routing (#190)
- Structural and content updates (#195)
- Improve the new revision (#215)
- Add frontmatter, add json output and search extensions, for improving SEO (#217)
- Updated tutorial (#223)
- Readme updates (#236)
- *(inference)* Update the output for inference get (#231)
- Improve tutorial and edit per nv style guide (#240)
- Add brev link to readme (#282)
- *(examples)* Add sandbox policy quickstart walkthrough (#266)
- Set the version to match the release version, add Adobe Launch tracking script, minor edits  (#287)

### Features

- *(dev)* Add k3d dev cluster
- *(sandbox)* Add basic network and file sandbox support
- *(server)* Add support for entity persistence
- *(sandboxes)* Initial kube sandbox impl
- *(sandbox)* Add ssh connect to sandbox + build agent harness
- *(cli)* Add run semantics to sandbox create
- Add mtls support to plaform
- *(cluster)* Add remote SSH deployment
- Add skill for reviewing gitlab mrs
- *(sandbox)* OPA policy engine with process-identity binding
- *(cluster)* Push locally-built images into k3s containerd for local dev (!16)
- *(server)* Add an inference router (!13)
- *(sandbox)* Add callable python exec API and refresh e2e coverage (!19)
- *(sandbox)* Add provider entity to support configuring tools such as claude, outlook, etc (!23)
- *(providers)* Inject provider credentials into sandbox child processes at runtime (!26)
- *(sandbox)* L7 protocol-aware inspection with TLS termination (!29)
- *(sandbox)* Enable port forwarding and setup openclaw (!33)
- *(sandbox)* Add --policy flag for custom sandbox policy and allow /dev/null in filesystem policy
- *(sandbox)* Add image build/push and fix cluster deploy (!34)
- *(cli)* Replace rsync with tar-over-SSH for sandbox file sync (!41)
- *(inference)* Inference interception and routing (!38)
- *(platform)* Cleanup api surface area and mtls flows (!39)
- *(cluster)* Speed up local deploy loop with incremental change tracking (!53)
- *(sandbox)* Move inference execution to sandbox-local routing (!79) (!52)
- *(sandbox)* Support live policy updates, history, and policy-aware logs (!55)
- *(sandbox)* VS Code Remote-SSH support with platform detection fix and network policy (!42)
- *(cli)* Add dynamic shell completion support (!59)
- *(cli)* Add runtime completers for sandbox/cluster/provider names (#44)
- *(gator)* Interactive TUI for Navigator (#57)
- *(sandbox)* Allow egress to private IP space via allowed_ips policy field (#60)
- *(tui)* Add port forwarding support to Gator (#81)
- *(skills)* Create nemoclaw-cli agent skill (#85)
- *(sandbox)* Support policy discovery and restrictive defaults on sandbox containers (#84)
- *(cli)* Add --from flag to sandbox create for unified image sources (#89)
- *(ci)* Add CLI binary builds and snapshot release to publish workflow (#110)
- *(cli)* Fall back to last-used sandbox when name is omitted (#70)
- *(e2e)* Parallelize e2e tests with pytest-xdist (default -n 5) (#102)
- *(policy)* Add validation layer to reject unsafe sandbox policies (#135)
- *(sandbox)* Upgrade Landlock to ABI V2 and fix sandbox venv PATH (#151)
- *(cli)* Restructure CLI commands for simpler UX (#156)
- *(proxy)* Support plain HTTP forward proxy for private IP endpoints (#158)
- *(cli)* Switch community sandbox registry to CloudFront CDN (#170)
- *(cli)* Improve sandbox provisioning status messages and UX (#175)
- *(cli)* Auto-create providers for explicit --provider names that match a known type (#183)
- Add Cloudflare tunnel auth support (#178)
- *(bootstrap)* Switch container registry from CloudFront CDN to GHCR with token auth (#167)
- *(tui)* Auto-refresh sandbox policy view when new versions are detected (#200)
- CLI improvements and fixes (#201)
- *(tui)* Add OpenShell splash screen and rebrand title bar (#210)
- *(inference)* Add sandbox-system inference route for platform-level inference (#209)
- *(cli)* Group help flags and make help for commands consistent with groups (#216)
- *(cli)* Detect port conflicts before gateway start, add sandbox delete --all, and improve spinner spacing (#225)
- *(sbom)* Add SBOM generation, license resolution, and CSV export tooling (#239)
- *(cluster)* Add NVIDIA GPU passthrough support for gateway start (#234)
- *(cli)* Launch sandbox editors via managed ssh include (#226)
- *(sandbox)* Add configurable imagePullPolicy for sandbox pods (#256)
- *(policy)* Add policy recommendation plumbing (#204) (#222)
- *(tui)* Support light terminal backgrounds with adaptive theme (#265)
- *(gateway)* Support adding remote and local gateways (#262)
- *(tui)* Add log copy and visual selection mode (#276)
- *(sandbox)* Add gpu sandbox scheduling support (#257)
- *(ci)* Add automated release workflow with patch version bumping (#284)

### Miscellaneous

- Add MCP server configuration from axiathon
- *(platform)* Hello world, intial commit
- *(docs)* Cleanup readme contributing
- *(sandbox)* Use docker for sandbox
- *(sandbox)* Fix sandbox and factory builds
- Cleanup misc docs files
- Cleanup docker/kube/helm infra
- Add claude/skills link to agent/skills
- *(sandbox)* Add networking tools to sandbox image
- Remove plans for now
- Cleanup and organize build files + publish containers
- Ignore plans for now
- *(ci)* Speed up ci builds and improve caching (!20)
- *(ci)* Add Python wheel publishing + tag release in CI (!22)
- Fix clippy warnings
- Ssh session set_nodelay(true)
- *(ci)* Enable wheel publishing on main
- *(ci)* Add Linux-hosted macOS wheel builds (!30)
- *(tests)* Cleanup unused tests
- *(docs)* Update uv install directions to ensure latest
- Changes for intial openclaw demo
- *(sandbox)* Enforce read-only git wire protocol on github.com (!46)
- *(build)* Disable e2e, speed up publish
- *(sandbox)* Unpin openclaw
- Cleanup agent configs
- Remove unnecessary cache config (#54)
- Update README.md to use nemoclaw registry (#63)
- Move tui-development skill to .agents directory (#65)
- *(ci)* Switch sccache from local disk to memcached backend (#68)
- Add open-source compliance files and SPDX headers (#71)
- Rename Navigator to NemoClaw across user facing contracts (#73)
- Simplify contributing workflow and documentation (#92)
- More contributing improvements (#103)
- *(ci)* Remove Gitlab CI config (#95)
- *(skills)* Consolidate spike output into single issue (#131)
- *(cluster)* Upgrade k3s to v1.35.2 and remove K3S_VERSION from mise.toml (#152)
- Rename project from NemoClaw to OpenShell (#198)
- Remove navigator references from codebase (#208)
- Replace all nemoclaw references with openshell (#214)
- *(docker)* Migrate base container images to nvcr.io/nvidia/base/ubuntu:noble-20251013 (#245)

### Refactor

- *(sandbox)* Consolidate policy data into YAML, remove rego data file (!18)
- *(agents)* Update agents context after the migration (#45)
- *(cli)* Remove global --tls-ca, --tls-cert, --tls-key flags (#62)
- *(policy)* Consolidate duplicated YAML struct hierarchies (#97)
- *(tui)* Rebrand Gator to Term/NemoClaw (#134)
- *(e2e)* Replace bash e2e tests with Rust integration tests (#150)
- *(inference)* Simplify routing — introduce inference.local, remove implicit catch-all (#146)
- *(python)* Rename navigator module to openshell and migrate config to gateway paths (#220)
- *(docker)* Rename server image to gateway (#246)
- *(cli)* Remove kubeconfig port, add doctor llm-help, update debug docs (#252)
- *(sandbox)* Move secrets to supervisor placeholders (#192)
- *(sandbox)* Sandboxes are managed as separate community images (#267)
- Rename navigator- crate prefix to openshell- (#277)

### Testing

- *(e2e)* Add e2e tests on skaffold
- Add pre-commit hooks
- Add basic lint and test checks to ci
- Bring back e2e tests on Github CI (#48)


