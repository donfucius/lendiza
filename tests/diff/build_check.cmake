# Build-time driver for the lendiza differential check.
#
# Invoked as a POST_BUILD step of the lendiza_diff_harness target:
#   cmake -DPYTHON=... -DCOMPARE=... -DHARNESS=... -DWORKDIR=... -P build_check.cmake
#
# Any suspect mismatch fails the build; exit 77 from compare.py (PyYAML or
# third_party data missing) is downgraded to a STATUS line so bare toolchains
# still build.
execute_process(
    COMMAND "${PYTHON}" "${COMPARE}" --gen --harness "${HARNESS}"
    WORKING_DIRECTORY "${WORKDIR}"
    RESULT_VARIABLE rc
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err)

if(NOT out STREQUAL "")
    message(STATUS "${out}")
endif()
if(NOT err STREQUAL "")
    message(STATUS "${err}")
endif()

if(rc EQUAL 77)
    message(STATUS "lendiza diff check skipped: PyYAML or third_party data missing")
elseif(NOT rc EQUAL 0)
    message(FATAL_ERROR "lendiza diff check failed with exit code ${rc}")
endif()
