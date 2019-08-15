load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def buildenv_repositories():
    http_archive(
        name = "bazel_skylib",
        urls = ["https://github.com/bazelbuild/bazel-skylib/archive/f80abf6578612d4b5dda3dd50337d22c8ac7b37d.tar.gz"],
        # latest as of 2019-05-02
        strip_prefix = "bazel-skylib-f80abf6578612d4b5dda3dd50337d22c8ac7b37d",
        sha256 = "b1afb26722971bf1f3e21fda94493a81e09995bf60be2b862746a2ed2cfd3284",
    )
