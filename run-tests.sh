#!/bin/sh
#
# This script is used to start test-wire-server before the test suite is run,
# because starting Keycloak requires that the redirect URL, which points to the
# test Wire server, is known.

tmpfile=$(mktemp)
rm ${tmpfile}
mkfifo ${tmpfile}
cargo run --locked test-wire-server > ${tmpfile} &
test_wire_server_pid=$!

# The test suite needs this environment variable in order to set up the test
# environment.
read TEST_WIRE_SERVER_ADDR < ${tmpfile}
export TEST_WIRE_SERVER_ADDR

echo \\nRunning nextest with arguments \"$@\"\\n
cargo nextest run --locked "$@"
test_exit_code="$?"

# Clean up.
docker kill keycloak && docker rm keycloak
kill ${test_wire_server_pid}
rm ${tmpfile}

exit "$test_exit_code"
