load("@bazel_skylib//lib:versions.bzl", "versions")

def check_bazel_version(x):
    versions.check(x)
