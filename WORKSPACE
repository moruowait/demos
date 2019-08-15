load("//tools:repositories.bzl", "buildenv_repositories")

buildenv_repositories()

load("//tools:def.bzl", "check_bazel_version")

check_bazel_version("0.27")

load("//go:repositories.bzl", "go_repositories")

go_repositories()

load("//go:def.bzl", "register_go_rules")

register_go_rules()
