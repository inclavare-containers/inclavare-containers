# Contribution to Inclavare Containers

Welcome to join Inclavare Containers project. Here's links to the primary ways to contribute to the Inclavare Containers project as an external contributor:

- [Reporting security issues](#reporting-security-issues)
- [Reporting general issues](#reporting-general-issues)
- [Pull Requests](#pull-requests)
- [Engage to help anything](#engage-to-help-anything)

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md) before making contribution.

## Reporting issues

Any Inclavare Containers user can potentially be a contributor. If you have any feedback for the project, feel free to open an issue via [NEW ISSUE](https://github.com/alibaba/inclavare-containers/issues/new).

Since Inclavare Containers development will be collaborated in a distributed manner, we appreciate **WELL-WRITTEN**, **DETAILED**, **EXPLICIT** issue reports. To make communication more efficient, we suggest everyone to search if your issue is an existing one before filing a new issue. If you find it to be existing, please append your details in the issue comments.

There are lot of cases for which you could open an issue:

- Bug report
- Feature request
- Performance issues
- Feature proposal
- Feature design
- Help wanted
- Doc incomplete
- Test improvement
- Any questions about the project, and so on

Please remind that when filing a new issue, do remove the sensitive data from your post. Sensitive data could be password, secret key, network locations, private business data and so on.

## Pull Requests 

Pull requests are the primary mechanism we use to change Inclavare Containers. Pull requests will be reviewed by one or more maintainers and merged when acceptable.

Before submitting a PR, we suggest you could take a look at the PR rules here.

- [Workspace Preparation](#workspace-preparation)
- [Branch Definition](#branch-definition)
- [Format C Codes](#format-c-codes)
- [Commit Rules](#commit-rules)
- [PR Description](#pr-description)
- [CI/CD Development](#cicd-development)

### Workspace Preparation

We assume you have a GitHub ID already, then you could finish the preparation in the following steps:

1. **FORK** Inclavare Containers to your repository. To make this work, you just need to click the button `Fork` in top-right corner of [Inclavare Containers](https://github.com/alibaba/inclavare-containers) main page. Then you will end up with your repository in `https://github.com/<username>/inclavare-containers`, in which `username` is your GitHub ID.
2. **CLONE** your own repository to develop locally. Use `git clone https://github.com/<username>/inclavare-containers.git` to clone repository to your local machine. Then you can create new branches to finish the change you wish to make.
3. **Set Remote** upstream to be Inclavare Containers using the following two commands:

```bash
git remote add upstream https://github.com/alibaba/inclavare-containers.git
git remote set-url --push upstream no-pushing
```

With this remote setting, you can check your git remote configuration like this:

```
$ git remote -v
origin     https://github.com/<username>/inclavare-containers.git (fetch)
origin     https://github.com/<username>/inclavare-containers.git (push)
upstream   https://github.com/alibaba/Inclavare Containers.git (fetch)
upstream   no-pushing (push)
```

With above, we can easily synchronize local branches with upstream branches.

### Branch Definition

Right now we assume every contribution via pull request is for the `master` branch in Inclavare Containers. There are several other branches such as rc branches, release branches and backport branches. Before officially releasing a version, we may checkout a rc (release candidate) branch for more testings. When officially releasing a version, there may be a release branch before tagging which will be deleted after tagging. When backporting some fixes to existing released version, we will checkout backport branches.

### Format C Codes

Inclavare Containers project uses `clang-format` to format C codes.

1. Install `clang-format`. Please make sure the version of `clang-format` must be 9.x or higher to get advanced features.

For Ubuntu:
```shell
sudo apt-get install -y clang-format-9
```

For CentOS 7:
```shell
sudo yum install -y clang
```

For CentOS 8:
```shell
sudo yum install -y git-clang-format
```

2. Format C code style using the following command:

```shell
clang-format -i foo.c
```

`clang-format` might generate unexpected results sometimes due to its limitation. To avoid the problem, you need to temporarily disable formatting with [special comments](https://clang.llvm.org/docs/ClangFormatStyleOptions.html#disabling-formatting-on-a-piece-of-code), e.g, forbidding formatting the following codes:

```C
// clang-format off
typedef enum {
        VERIFICATION_TYPE_QVL,
        VERIFICATION_TYPE_QEL
} quote_sgx_ecdsa_verification_type_t;
// clang-format on
```

Please refer to [this page](https://clang.llvm.org/docs/ClangFormatStyleOptions.html) for the details about the options of `clang-format`.

### Commit Rules

#### Commit Message

The commit messages should answer two questions: what changed and why this change was made. The subject line should feature the what and the commit body should describe the why, e.g:

```
rune/libenclave: work around nanosleep() issue
    
nanosleep() may return the remaining duration longer than
requested one due to timer slack.
```

The format can be described more formally:

```
<subsystem>: <what changed>
<BLANK LINE>
<why this change was made>
<BLANK LINE>
<FIX LINE>
<SOB LINE>
```

The first line is the subject and should be no longer than 50 characters, the other lines should be wrapped at 72 characters (see [this blog post](https://preslav.me/2015/02/21/what-s-with-the-50-72-rule/) for why).

If the change affects more than one subsystem, you can use comma to separate them like `rune/libenclave,shim:`.

The first letter of <what changed> is lowercase, without ending with a full stop.

If the change affects many subsystems, you can use ```*``` instead, like ```*:``` 

The message of commit body should describe why the change was made and how the code works at the high level.

`<FIX LINE>` is optional. Please write the issue number at `<FIX LINE>` when your commit fixes an issue on Inclavare Containers project. Once the commit is submitted, the issue of Inclavare Containers project will be automatically closed. For example, `Fixes: #123` means this commit resolves the issue number 123.

#### Sign your work 

A DCO sign-off is a line placed at the end of a commit message containing a contributor's signature.
In adding this, the contributor certifies that they have the right to contribute the material.

Here are the steps to sign one's work:

Once the contributor certifies the DCO below (from [developercertificate.org](https://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

The contributor then just needs to add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@example.com>

One's real name must be used (no pseudonyms or anonymous contributions).

The easiest way to do this is, assuming `user.name` and `user.email` are set via 
the git cli configuration (`git config`), is to sign commits automatically via `git commit -s`.

Finally, the `git log` information for a commit should show something like this:

```
Author: Joe Smith <joe.smith@example.com>
Date:   Thu Feb 2 11:41:15 2018 -0800

    Update README

    Fixes: #123
    Signed-off-by: Joe Smith <joe.smith@example.com>
```

Notice the `Author` and `Signed-off-by` lines match. If they don't,
the PR will be rejected by the automated DCO check.

### PR Description

PR is the only way to make change to Inclavare Containers project. To help reviewers, we actually encourage contributors to make PR description as detailed as possible.

### CI/CD Development

When a PR involves the development of new features, the contributor **REQUIRES** to write a new CI/CD workflow or integrate the test codes into existing workflow.

CI/CD development is as important as code development, which can detect the potential errors as early as possible and save the debugging time. Please refer to [WIKI](https://github.com/alibaba/inclavare-containers/wiki) page for the detailed contents about Inclavare Containers CI/CD development.

## Engage to help anything

GitHub is the primary place for Inclavare Containers contributors to collaborate. Although contributions via PR is an explicit way to help, we still call for any other types of helps.

- Reply to other's issues if you could;
- Help solve other user's problems;
- Help review other's PR design;
- Help review other's codes in PR;
- Discuss about Inclavare Containers to make things clearer;
- Advocate Inclavare Containers technology beyond GitHub;
- Write blogs on Inclavare Containers, and so on.

In a word, **ANY HELP CAN BE A CONTRIBUTION.**

# Credits
Some contents in this documents have been borrowed from [OpenYurt](https://github.com/alibaba/openyurt/blob/master/CONTRIBUTING.md) project.
