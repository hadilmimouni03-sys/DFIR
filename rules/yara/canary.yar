/*
    canary.yar -- pipeline instrumentation, NOT threat signatures.

    A clean host produces zero YARA hits, which is indistinguishable from a
    scanner that silently failed to run. These rules match a string that
    appears in no real software, planted by the attack simulation
    (tests/attack_chain_simulation.py, the win_yara_canary technique). If the
    canary fires and nothing else does, the file-scan pipeline -- discovery ->
    compile -> scan -> detection -> database -- is proven working and the host
    is genuinely clean. If the canary does NOT fire after the simulation
    planted it, the pipeline is broken and every "0 hits" elsewhere is
    untrustworthy.

    Safe to leave in the corpus permanently: it can only match files that
    deliberately contain the canary string, so it never fires on real evidence.
*/

rule MDY_CANARY_FILE_PIPELINE
{
    meta:
        severity = "info"
        score = 0
        description = "Pipeline canary. Not a threat -- proves the file YARA scan ran."
        author = "MiniDFIR"

    strings:
        $canary = "MINIDFIR-CANARY-2f8a1c9e" ascii wide nocase

    condition:
        $canary
}
