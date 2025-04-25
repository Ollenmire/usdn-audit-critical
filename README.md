# USDN Rebase Callback Vulnerability Audit & PoC

This repository contains the contracts, tests, and Proof of Concept (PoC) scripts related to the audit finding of a critical Rebase Denial-of-Service vulnerability in the USDN token contract.

## Vulnerability Summary

The original `Usdn.sol` contract's `rebase` function makes an external call to a configurable `_rebaseHandler` without sufficient gas stipends or error handling. This allows a malicious handler to block the `rebase` function via revert or gas exhaustion attacks, preventing the core divisor update mechanism and causing economic harm.

## Reproducing the Vulnerability and Verification

The following steps reproduce the vulnerability demonstration and verify the effectiveness of the proposed fix (Gas Stipend Method) using Foundry on a Unix-like environment.

1.  **Install Foundry** ([Installation Guide](https://book.getfoundry.sh/getting-started/installation)):
    ```bash
    $ curl -L https://foundry.paradigm.xyz | bash && foundryup
    ```
    *(Follow instructions and restart your shell if necessary)*

2.  **Clone Repository & Install Dependencies**:
    ```bash
    # Replace with the actual repository URL if needed
    git clone https://github.com/Ollenmire/usdn-audit-critical.git usdn-audit-critical
    cd usdn-audit-critical

    # Initialize and fetch the exact submodule commits tracked by the repository
    git submodule update --init --recursive

    # Install specific library versions required by the project
    forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 vectorized/solady@v0.0.228 foundry-rs/forge-std --no-commit
    ```
    *(Note: `forge install` might be redundant after `submodule update`, but ensures dependencies are linked)*

3.  **Start Anvil (Local Test Node)**:
    Open a **separate terminal window**, navigate to the `usdn-audit-critical` directory, and run:
    ```bash
    anvil
    ```
    Keep this terminal running Anvil in the background.

4.  **Create Logs Directory**:
    In your **original terminal window** (inside the `usdn-audit-critical` directory), create the directory for logs:
    ```bash
    mkdir logs
    ```

5.  **Run PoC Script**:
    Clean artifacts and run the comprehensive PoC script:
    ```bash
    forge clean && forge script script/FullRebaseExploitPoC.s.sol:FullRebaseExploitPoC --rpc-url http://localhost:8545 --broadcast -vvv 2>&1 | tee logs/full_rebase_poc.log
    ```

6.  **Observe Vulnerability Results**:
    Examine the script output logs. You should observe confirmations that the attacks on the *vulnerable* contract succeeded (meaning the rebase failed):
    ```log
    == Logs ==
    ...
    --- Testing Vulnerable Contract: Revert Attack ---
    Malicious callback (REVERT) set as handler for Vulnerable contract.
    Result: Expected: Rebase failed due to revert, divisor unchanged.
    --- Testing Vulnerable Contract: Gas Exhaustion Attack ---
    Malicious callback configured for GAS_EXHAUSTION.
    Result: Expected: Rebase failed due to gas exhaustion, divisor unchanged.
    ...
    ```
    The traces section will also show the `[Revert]` and `[MemoryOOG]` errors for these calls.

7.  **Observe Mitigation Verification**:
    Continue examining the logs for the tests run against the *fixed* contract (`UsdnFixed.sol`):
    ```log
    == Logs ==
    ...
    --- Testing Fixed Contract: Revert Attack ---
    Malicious callback (REVERT) set as handler for Fixed contract.
    Result: Expected: Rebase succeeded, divisor changed, callback trapped.
    --- Testing Fixed Contract: Gas Exhaustion Attack ---
    Malicious callback configured for GAS_EXHAUSTION.
    Result: Expected: Rebase succeeded, divisor changed, callback trapped.
    ...
    ```
    These logs, along with the final summary `CORE VERIFICATION COMPLETE: All core tests passed. Gas stipend fix is effective.`, confirm that the Gas Stipend Method successfully prevents the DoS attacks.

8.  **Review Detailed Logs (Optional)**:
    A complete, warning-free execution log is saved to `logs/full_rebase_poc.log` for detailed review.

## Files of Interest

*   `src/Usdn/Usdn.sol`: The original, vulnerable contract.
*   `src/Usdn/UsdnFixed.sol`: The contract with the gas stipend mitigation applied.
*   `script/FullRebaseExploitPoC.s.sol`: The Foundry script used to demonstrate the vulnerability and verify the fix.
*   `logs/`: Directory containing execution logs. 