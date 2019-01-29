#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

sourceDir="$DIR/../OAKProxy"
packageDir="$DIR/packages"

pushd "$sourceDir"
dotnet.exe publish -c "Release" -f "netcoreapp2.2" -r "win10-x64" --self-contained false
dotnet.exe publish -c "Release" -f "net472" -r "win10-x64" --self-contained false
popd

rm -rf "$packageDir"
mkdir "$packageDir"

zip -r -9 "$packageDir/oakproxy-core22.zip" "$sourceDir/bin/Release/netcoreapp2.2/win10-x64/publish"
zip -r -9 "$packageDir/oakproxy-net472.zip" "$sourceDir/bin/Release/net472/win10-x64/publish"

