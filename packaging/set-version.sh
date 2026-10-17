#!/bin/sh
# Stamp VERSION (from the release tag) into Cargo.toml and Cargo.lock, so the tag is the
# only place a release version is written.
set -eu
version=${1:?usage: set-version.sh VERSION}
echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || {
    echo "invalid version: $version" >&2
    exit 1
}
cd "$(dirname "$0")/.."
VERSION=$version perl -0pi -e 's/(\[package\]\nname = "localname"\nversion = )"[^"]*"/$1"$ENV{VERSION}"/' Cargo.toml
VERSION=$version perl -0pi -e 's/(\nname = "localname"\nversion = )"[^"]*"/$1"$ENV{VERSION}"/' Cargo.lock
grep -q "^version = \"$version\"" Cargo.toml && grep -A1 '^name = "localname"$' Cargo.lock | grep -q "\"$version\"" || {
    echo "failed to set version $version" >&2
    exit 1
}
echo "localname version set to $version"
