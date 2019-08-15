load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

def register_go_rules():
    # rules_go go rules
    go_rules_dependencies()
    go_register_toolchains()

    # gazelle
    gazelle_dependencies()
