# Table of Contents
1. [Minimum Recommended Skillset](#minimum-recommended-skillset)
1. [Required Reading](#required-reading)
1. [Development Practices](#development-practices)
   1. [Share Early, Share Often](#share-early-share-often)
   1. [Testing](#testing)
   1. [Code Documentation and Commenting](#code-documentation-and-commenting)
   1. [Model Git Commit Messages](#model-git-commit-messages)
   1. [Ideal Git Commit Structure](#ideal-git-commit-structure)
   1. [Sign Your Git Commits](#sign-your-git-commits)
   1. [Code Spacing and formatting](#code-spacing-and-formatting)
   1. [Pointing to Remote Dependent Branches in Go Modules](#pointing-to-remote-dependent-branches-in-go-modules)
   1. [Use of Log Levels](#use-of-log-levels)
   1. [Use of Golang submodules](#use-of-golang-submodules)
1. [Code Approval Process](#code-approval-process)
   1. [Code Review](#code-review)
   1. [Rework Code (if needed)](#rework-code-if-needed)
   1. [Acceptance](#acceptance)
   1. [Review Bot](#review-bot)
1. [Contribution Standards](#contribution-standards)
   1. [Contribution Checklist](#contribution-checklist)
   1. [Licensing of Contributions](#licensing-of-contributions)


# Substantial contributions only

Due to the prevalence of automated analysis and pull request authoring tools
and online competitions that incentivize creating commits in popular
repositories, the maintainers of this project are flooded with trivial pull
requests that only change some typos or other insubstantial content (e.g. the
year in the license file).
If you are an honest user that wants to contribute to this project, please
consider that every pull request takes precious time from the maintainers to
review and consider the impact of changes. Time that could be spent writing
features or fixing bugs.
If you really want to contribute, consider reviewing and testing other users'
pull requests instead. Or add value to the project by writing unit tests.


# Minimum Recommended Skillset

The following list is a set of core competencies that we recommend you possess
before you really start attempting to contribute code to the project.  These are
not hard requirements as we will gladly accept code contributions as long as
they follow the guidelines set forth on this page.  That said, if you don't have
the following basic qualifications you will likely find it quite difficult to
contribute to the core layers of Bitcoin. However, there are still a number
of low-hanging fruit which can be tackled without having full competency in the
areas mentioned below. 

- A reasonable understanding of bitcoin at a high level (see the
  [Required Reading](#required-reading) section for the original white paper)
- A reasonable understanding of the Bitcoin at a high level
- Experience in some type of C-like language
- An understanding of data structures and their performance implications
- Familiarity with unit testing
- Debugging experience
- Ability to understand not only the area you are making a change in, but also
  the code your change relies on, and the code which relies on your changed code

Building on top of those core competencies, the recommended skill set largely
depends on the specific areas you are looking to contribute to.  For example,
if you wish to contribute to the cryptography code, you should have a good
understanding of the various aspects involved with cryptography such as the
security and performance implications.


# Required Reading

- [Effective Go](https://golang.org/doc/effective_go.html) - The entire `btcwallet` 
  project follows the guidelines in this document. For your code to be
  accepted, it must follow the guidelines therein.
- [Original Satoshi Whitepaper](https://bitcoin.org/bitcoin.pdf) - This is the
  white paper that started it all. Having a solid foundation to build on will
  make the code much more comprehensible.


# Development Practices

Developers are expected to work in their own trees and submit pull requests
when they feel their feature or bug fix is ready for integration into the
master branch.

## Share Early, Share Often

We firmly believe in the share early, share often approach. The basic premise
of the approach is to announce your plans **before** you start work, and once
you have started working, craft your changes into a stream of small and easily
reviewable commits.

This approach has several benefits:

- Announcing your plans to work on a feature **before** you begin work avoids
  duplicate work
- It permits discussions which can help you achieve your goals in a way that is
  consistent with the existing architecture
- It minimizes the chances of you spending time and energy on a change that
  might not fit with the consensus of the community or existing architecture and
  potentially be rejected as a result
- The quicker your changes are merged to master, the less time you will need to
  spend rebasing and otherwise trying to keep up with the main code base

## Testing

One of the major design goals of all of `btcwallet`'s packages and the daemon
itself is to aim for a high degree of test coverage. This is financial software
so bugs and regressions in the core logic can cost people real money. For this
reason every effort must be taken to ensure the code is as accurate and
bug-free as possible. Thorough testing is a good way to help achieve that goal.

Unless a new feature you submit is completely trivial, it will probably be
rejected unless it is also accompanied by adequate test coverage for both
positive and negative conditions. That is to say, the tests must ensure your
code works correctly when it is fed correct data as well as incorrect data
(error paths).


Go provides an excellent test framework that makes writing test code and
checking coverage statistics straightforward. For more information about the
test coverage tools, see the [golang cover blog
post](https://blog.golang.org/cover).

A quick summary of test practices follows:

- All new code should be accompanied by tests that ensure the code behaves
  correctly when given expected values, and, perhaps even more importantly, that
  it handles errors gracefully

- When you fix a bug, it should be accompanied by tests which exercise the bug
  to both prove it has been resolved and to prevent future regressions


## Code Documentation and Commenting

- At a minimum every function must be commented with its intended purpose and
  any assumptions that it makes
  - Function comments must always begin with the name of the function per
    [Effective Go](https://golang.org/doc/effective_go.html).

  - Function comments should be complete sentences since they allow a wide
    variety of automated presentations such as [godoc.org](https://godoc.org).

  - The general rule of thumb is to look at it as if you were completely
    unfamiliar with the code and ask yourself, would this give me enough
    information to understand what this function does and how I'd probably want
    to use it?

  - Exported functions should also include detailed information the caller of
    the function will likely need to know and/or understand:<br /><br />

**WRONG**
```go
// generates a revocation key
func DeriveRevocationPubkey(commitPubKey *btcec.PublicKey,
	revokePreimage []byte) *btcec.PublicKey {
```
**RIGHT**
```go
// DeriveRevocationPubkey derives the revocation public key given the
// counterparty's commitment key, and revocation preimage derived via a
// pseudo-random-function. In the event that we (for some reason) broadcast a
// revoked commitment transaction, then if the other party knows the revocation
// preimage, then they'll be able to derive the corresponding private key to
// this private key by exploiting the homomorphism in the elliptic curve group:
//    * https://en.wikipedia.org/wiki/Group_homomorphism#Homomorphisms_of_abelian_groups
//
// The derivation is performed as follows:
//
//   revokeKey := commitKey + revokePoint
//             := G*k + G*h
//             := G * (k+h)
//
// Therefore, once we divulge the revocation preimage, the remote peer is able to
// compute the proper private key for the revokeKey by computing:
//   revokePriv := commitPriv + revokePreimge mod N
//
// Where N is the order of the sub-group.
func DeriveRevocationPubkey(commitPubKey *btcec.PublicKey,
	revokePreimage []byte) *btcec.PublicKey {
```
- Comments in the body of the code are highly encouraged, but they should
  explain the intention of the code as opposed to just calling out the
  obvious<br /><br />

**WRONG**
```go
// return err if amt is less than 546
if amt < 546 {
	return err
}
```
**RIGHT**
```go
// Treat transactions with amounts less than the amount which is considered dust
// as non-standard.
if amt < 546 {
	return err
}
```
**NOTE:** The above should really use a constant as opposed to a magic number,
but it was left as a magic number to show how much of a difference a good
comment can make.

## Code Spacing and formatting

Code in general (and Open Source code specifically) is _read_ by developers many
more times during its lifecycle than it is modified. With this fact in mind, the
Golang language was designed for readability (among other goals).
While the enforced formatting of `go fmt` and some best practices already
eliminate many discussions, the resulting code can still look and feel very
differently among different developers.

We aim to enforce a few additional rules to unify the look and feel of all code
in `btcwallet` to help improve the overall readability.

**Please refer to the [code formatting rules
document](./code_formatting_rules.md)** to see the list of additional style
rules we enforce.

## Model Git Commit Messages

This project prefers to keep a clean commit history with well-formed commit
messages. This section illustrates a model commit message and provides a bit
of background for it. This content was originally created by Tim Pope and made
available on his website, however that website is no longer active, so it is
being provided here.

Here’s a model Git commit message:

```text
Short (50 chars or less) summary of changes

More detailed explanatory text, if necessary.  Wrap it to about 72
characters or so.  In some contexts, the first line is treated as the
subject of an email and the rest of the text as the body.  The blank
line separating the summary from the body is critical (unless you omit
the body entirely); tools like rebase can get confused if you run the
two together.

Write your commit message in the present tense: "Fix bug" and not "Fixed
bug."  This convention matches up with commit messages generated by
commands like git merge and git revert.

Further paragraphs come after blank lines.

- Bullet points are okay, too
- Typically a hyphen or asterisk is used for the bullet, preceded by a
  single space, with blank lines in between, but conventions vary here
- Use a hanging indent
```

Here are some of the reasons why wrapping your commit messages to 72 columns is
a good thing.

- git log doesn't do any special wrapping of the commit messages. With
  the default pager of less -S, this means your paragraphs flow far off the edge
  of the screen, making them difficult to read. On an 80 column terminal, if we
  subtract 4 columns for the indent on the left and 4 more for symmetry on the
  right, we’re left with 72 columns.

- git format-patch --stdout converts a series of commits to a series of emails,
  using the messages for the message body.  Good email netiquette dictates we
  wrap our plain text emails such that there’s room for a few levels of nested
  reply indicators without overflow in an 80 column terminal.
  

In addition to the Git commit message structure adhered to within the daemon
all short-[commit messages are to be prefixed according to the convention
outlined in the Go project](https://golang.org/doc/contribute.html#change). All
commits should begin with the subsystem or package primarily affected by the
change. In the case of a widespread change, the packages are to be delimited by
either a '+' or a ','. This prefix seems minor but can be extremely helpful in
determining the scope of a commit at a glance, or when bug hunting to find a
commit which introduced a bug or regression. 

## Ideal Git Commit Structure

Within the project we prefer small, contained commits for a pull request over a
single giant commit that touches several files/packages. Ideal commits build on
their own, in order to facilitate easy usage of tools like `git bisect` to `git
cherry-pick`. It's preferred that commits contain an isolated change in a
single package. In this case, the commit header message should begin with the
prefix of the modified package. For example, if a commit was made to modify the
`lnwallet` package, it should start with `lnwallet: `. 

In the case of changes that only build in tandem with changes made in other
packages, it is permitted for a single commit to be made which contains several
prefixes such as: `chain+rpc`. This prefix structure along with the requirement
for atomic contained commits (when possible) make things like scanning the set
of commits and debugging easier. In the case of changes that touch several
packages, and can only compile with the change across several packages, a
`multi: ` prefix should be used.

Examples of common patterns w.r.t commit structures within the project:

  * It is common that during the work on a PR, existing bugs are found and
    fixed. If they can be fixed in isolation, they should have their own
    commit. 

  * File restructuring like moving a function to another file or changing order
    of functions: with a separate commit because it is much easier to review
    the real changes that go on top of the restructuring.

  * Preparatory refactorings that are functionally equivalent: own commit.

  * Project or package wide file renamings should be in their own commit.

  * Ideally if a new package/struct/sub-system is added in a PR, there should
    be a single commit which adds the new functionality, with follow up
    individual commits that begin to integrate the functionality within the
    codebase.

  * If a PR only fixes a trivial issue, such as updating documentation on a
    small scale, fix typos, or any changes that do not modify the code, the
    commit message of the HEAD commit of the PR should end with `[skip ci]` to
    skip the CI checks. When pushing to such an existing PR, the latest commit
    being pushed should end with `[skip ci]` as to not inadvertently trigger the
    CI checks.
    
## Sign your git commits

When contributing to `btcwallet` it is recommended to sign your git commits.
This is easy to do and will help in assuring the integrity of the tree. See
[mailing list
entry](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2014-May/005877.html)
for more information.

### How to sign your commits?

Provide the `-S` flag (or `--gpg-sign`) to git commit when you commit
your changes, for example

```shell
$  git commit -m "Commit message" -S
```

Optionally you can provide a key id after the `-S` option to sign with a
specific key.

To instruct `git` to auto-sign every commit, add the following lines to your
`~/.gitconfig` file:

```text
[commit]
        gpgsign = true
```

### What if I forgot?

You can retroactively sign your previous commit using `--amend`, for example

```shell
$  git commit -S --amend
```

If you need to go further back, you can use the interactive rebase command with
'edit'. Replace `HEAD~3` with the base commit from which you want to start.

```shell
$  git rebase -i HEAD~3
```

Replace 'pick' by 'edit' for the commit that you want to sign and the rebasing
will stop after that commit. Then you can amend the commit as above.
Afterwards, do

```shell
$  git rebase --continue
```

As this will rewrite history, you cannot do this when your commit is already
merged. In that case, too bad, better luck next time.

If you rewrite history for another reason - for example when squashing commits
- make sure that you re-sign as the signatures will be lost.

Multiple commits can also be re-signed with `git rebase`. For example, signing
the last three commits can be done with:

```shell
$  git rebase --exec 'git commit --amend --no-edit -n -S' -i HEAD~3
```

### How to check if commits are signed?

Use `git log` with `--show-signature`,

```shell
$  git log --show-signature
```

You can also pass the `--show-signature` option to `git show` to check a single
commit.

## Use of Log Levels

There are six log levels available: `trace`, `debug`, `info`, `warn`, `error`
and `critical`.

Only use `error` for internal errors that are never expected to happen during
normal operation. No event triggered by external sources (rpc, chain backend,
etc) should lead to an `error` log.

## Use of Golang submodules

Changes to packages that are their own submodules (e.g. they contain a `go.mod`
and `go.sum` file, for example `walletdb/go.mod`) require a specific process.
We want to avoid the use of local replace directives in the root `go.mod`,
therefore changes to a submodule are a bit involved.

The main process for updating and then using code in a submodule is as follows:

 - Create a PR for the changes to the submodule itself (e.g. edit something in
   the `tor` package)

 - Wait for the PR to be merged and a new tag (for example `walletdb/v1.0.x`)
   to be pushed.

 - Create a second PR that bumps the updated submodule in the root `go.mod` and
   uses the new functionality in the main module.

Of course the two PRs can be opened at the same time and be built on top of
each other. But the merge and tag push order should always be maintained.

# Code Approval Process

This section describes the code approval process that is used for code
contributions. This is how to get your changes into `btcwallet`.

## Code Review

All code which is submitted will need to be reviewed before inclusion into the
master branch. This process is performed by the project maintainers and usually
other committers who are interested in the area you are working in as well.

### Code Review Timeframe

The timeframe for a code review will vary greatly depending on factors such as
the number of other pull requests which need to be reviewed, the size and
complexity of the contribution, how well you followed the guidelines presented
on this page, and how easy it is for the reviewers to digest your commits.  For
example, if you make one monolithic commit that makes sweeping changes to things
in multiple subsystems, it will obviously take much longer to review.  You will
also likely be asked to split the commit into several smaller, and hence more
manageable, commits.

Keeping the above in mind, most small changes will be reviewed within a few
days, while large or far-reaching changes may take weeks.  This is a good reason
to stick with the [Share Early, Share Often](#share-early-share-often)
development practice outlined above.

### What is the review looking for?

The review is mainly ensuring the code follows the [Development
Practices](#development-practices) and [Code Contribution
Standards](#contribution-standards). However, there are a few other checks
which are generally performed as follows:

- The code is stable and has no stability or security concerns.

- The code is properly using existing APIs and generally fits well into the
  overall architecture.

- The change is not something which is deemed inappropriate by community
  consensus.

## Rework Code (if needed)

After the code review, the change will be accepted immediately if no issues are
found. If there are any concerns or questions, you will be provided with
feedback along with the next steps needed to get your contribution merged with
master. In certain cases the code reviewer(s) or interested committers may help
you rework the code, but generally you will simply be given feedback for you to
make the necessary changes.

During the process of responding to review comments, we prefer that changes be
made with [fixup commits](https://robots.thoughtbot.com/autosquashing-git-commits). 
The reason for this is twofold: it makes it easier for the reviewer to see
what changes have been made between versions (since Github doesn't easily show
prior versions like Critique) and it makes it easier on the PR author as they
can set it to auto squash the fix up commits on rebase.

This process will continue until the code is finally accepted.

## Acceptance

Once your code is accepted, it will be integrated with the master branch. After
2+ (sometimes 1) LGTM's (approvals) are given on a PR, it's eligible to land in
master. At this final phase, it may be necessary to rebase the PR in order to
resolve any conflicts and also squash fix up commits. Ideally, the set of
[commits by new contributors are PGP signed](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work), 
although this isn't a strong requirement (but we prefer it!). In order to keep
these signatures intact, we prefer using merge commits. PR proposers can use
`git rebase --signoff` to sign and rebase at the same time as a final step.

Rejoice as you will now be listed as a [contributor](https://github.com/btcsuite/btcd/graphs/contributors)!

# Contribution Standards

## Contribution Checklist

See [template](https://github.com/btcsuite/btcwallet/blob/master/.github/pull_request_template.md). 

## Licensing of Contributions
****
All contributions must be licensed with the [MIT
license](https://github.com/btcsuite/btcwallet/blob/master/LICENSE). This is
the same license as all of the code found within `btcwallet`.


# Acknowledgements
This document was heavily inspired by a [similar document outlining the code
contribution](https://github.com/btcsuite/btcd/blob/master/docs/code_contribution_guidelines.md)
guidelines for btcd. 
