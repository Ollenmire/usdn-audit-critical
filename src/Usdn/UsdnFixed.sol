// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {FixedPointMathLib} from "solady/src/utils/FixedPointMathLib.sol";

import {IRebaseCallback} from "../interfaces/Usdn/IRebaseCallback.sol";
import {IUsdn} from "../interfaces/Usdn/IUsdn.sol";

// Custom errors - include necessary errors from IUsdnErrors
error UsdnInsufficientBalance(
    address sender,
    uint256 requested,
    uint256 available
);
error UsdnMaxTokensExceeded(uint256 value);
error UsdnInvalidDivisor();
error UsdnZeroShares(); // Assuming this might be needed

/**
 * @title USDN Token Contract (Fixed Version)
 * @notice Fixed version of the USDN token that protects against malicious callbacks
 * by implementing a gas stipend for the rebase callback.
 * @dev This version includes fixes for compilation errors found previously.
 */
contract UsdnFixed is IUsdn, ERC20Permit, ERC20Burnable, AccessControl {
    /**
     * @dev Enum representing the rounding options when converting from shares to tokens.
     * @param Down Rounds down to the nearest integer (towards zero).
     * @param Closest Rounds to the nearest integer.
     * @param Up Rounds up to the nearest integer (towards positive infinity).
     */
    enum Rounding {
        Down,
        Closest,
        Up
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Constants                                 */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IUsdn
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @inheritdoc IUsdn
    bytes32 public constant REBASER_ROLE = keccak256("REBASER_ROLE");

    /// @inheritdoc IUsdn
    uint256 public constant MAX_DIVISOR = 1e18;

    /// @inheritdoc IUsdn
    uint256 public constant MIN_DIVISOR = 1e9;

    /// @notice The name of the USDN token.
    string internal constant NAME = "Ultimate Synthetic Delta Neutral";

    /// @notice The symbol of the USDN token.
    string internal constant SYMBOL = "USDN";

    /// @notice Fixed gas stipend for rebase callbacks to prevent gas exhaustion attacks
    uint256 internal constant REBASE_CALLBACK_GAS_STIPEND = 100_000;

    /* -------------------------------------------------------------------------- */
    /*                              Storage variables                             */
    /* -------------------------------------------------------------------------- */

    /// @notice Mapping of the number of shares held by each account.
    mapping(address account => uint256) internal _shares;

    /// @notice The sum of all the shares.
    uint256 internal _totalShares;

    /// @notice The divisor used for conversion between shares and tokens.
    uint256 internal _divisor = MAX_DIVISOR;

    /// @notice Address of a contract to be called upon a rebase event.
    IRebaseCallback internal _rebaseHandler;

    /* -------------------------------------------------------------------------- */
    /*                                 Constructor                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Constructs the USDN token contract.
     * @param initialMinter The initial address to be granted the MINTER_ROLE, can be address(0).
     * @param initialRebaser The initial address to be granted the REBASER_ROLE, can be address(0).
     */
    constructor(
        address initialMinter,
        address initialRebaser
    ) ERC20(NAME, SYMBOL) ERC20Permit(NAME) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        if (initialMinter != address(0)) {
            _grantRole(MINTER_ROLE, initialMinter);
        }
        if (initialRebaser != address(0)) {
            _grantRole(REBASER_ROLE, initialRebaser);
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                          ERC-20 Override functions                         */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IERC20
    function totalSupply()
        public
        view
        virtual
        override(ERC20, IERC20)
        returns (uint256)
    {
        // Formula: total supply = total shares / divisor
        return _convertToTokens(_totalShares, Rounding.Down, _divisor);
    }

    /// @inheritdoc IERC20
    function balanceOf(
        address account
    ) public view virtual override(ERC20, IERC20) returns (uint256) {
        // Formula: balance = shares / divisor
        return _convertToTokens(_shares[account], Rounding.Down, _divisor);
    }

    /// @inheritdoc IERC20
    function transfer(
        address to,
        uint256 amount
    ) public virtual override(ERC20, IERC20) returns (bool) {
        address owner = _msgSender();
        _update(owner, to, amount);
        return true;
    }

    /// @inheritdoc IERC20
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual override(ERC20, IERC20) returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _update(from, to, amount);
        return true;
    }

    /// @inheritdoc ERC20Burnable
    function burn(
        uint256 amount
    ) public virtual override(ERC20Burnable, IUsdn) {
        _update(_msgSender(), address(0), amount);
    }

    /// @inheritdoc ERC20Burnable
    function burnFrom(
        address account,
        uint256 amount
    ) public virtual override(ERC20Burnable, IUsdn) {
        _spendAllowance(account, _msgSender(), amount);
        _update(account, address(0), amount);
    }

    /// @inheritdoc IERC20Permit
    function nonces(
        address owner
    )
        public
        view
        virtual
        override(ERC20Permit, IERC20Permit)
        returns (uint256)
    {
        return super.nonces(owner);
    }

    /* -------------------------------------------------------------------------- */
    /*                             View functions                                */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IUsdn
    function totalShares() external view returns (uint256 shares_) {
        return _totalShares;
    }

    /// @inheritdoc IUsdn
    function sharesOf(address account) external view returns (uint256 shares_) {
        return _shares[account];
    }

    /// @inheritdoc IUsdn
    function convertToShares(
        uint256 amountTokens
    ) external view returns (uint256 shares_) {
        return _convertToShares(amountTokens, Rounding.Down, _divisor);
    }

    /// @inheritdoc IUsdn
    function convertToTokens(
        uint256 amountShares
    ) external view returns (uint256 tokens_) {
        return _convertToTokens(amountShares, Rounding.Closest, _divisor);
    }

    /// @inheritdoc IUsdn
    function convertToTokensRoundUp(
        uint256 amountShares
    ) external view returns (uint256 tokens_) {
        return _convertToTokens(amountShares, Rounding.Up, _divisor);
    }

    /// @inheritdoc IUsdn
    function divisor() external view returns (uint256 divisor_) {
        return _divisor;
    }

    /// @inheritdoc IUsdn
    function rebaseHandler()
        external
        view
        returns (IRebaseCallback rebaseHandler_)
    {
        return _rebaseHandler;
    }

    /// @inheritdoc IUsdn
    function maxTokens() public view returns (uint256 maxTokens_) {
        return type(uint256).max / _divisor;
    }

    /* -------------------------------------------------------------------------- */
    /*                         Share Transfer functions                         */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IUsdn
    function transferShares(
        address to,
        uint256 value
    ) external returns (bool success_) {
        address owner = _msgSender();
        _transferShares(
            owner,
            to,
            value,
            _convertToTokens(value, Rounding.Closest, _divisor)
        );
        return true;
    }

    /// @inheritdoc IUsdn
    function transferSharesFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool success_) {
        address spender = _msgSender();
        uint256 d = _divisor;
        _spendAllowance(from, spender, _convertToTokens(value, Rounding.Up, d));
        _transferShares(
            from,
            to,
            value,
            _convertToTokens(value, Rounding.Closest, d)
        );
        return true;
    }

    /// @inheritdoc IUsdn
    function burnShares(uint256 value) external {
        _burnShares(
            _msgSender(),
            value,
            _convertToTokens(value, Rounding.Closest, _divisor)
        );
    }

    /// @inheritdoc IUsdn
    function burnSharesFrom(address account, uint256 value) public {
        uint256 d = _divisor;
        _spendAllowance(
            account,
            _msgSender(),
            _convertToTokens(value, Rounding.Up, d)
        );
        _burnShares(
            account,
            value,
            _convertToTokens(value, Rounding.Closest, d)
        );
    }

    /* -------------------------------------------------------------------------- */
    /*                            Privileged functions                            */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IUsdn
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /// @inheritdoc IUsdn
    function mintShares(
        address to,
        uint256 amount
    ) external onlyRole(MINTER_ROLE) returns (uint256 mintedTokens_) {
        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        mintedTokens_ = _convertToTokens(amount, Rounding.Closest, _divisor);
        _updateShares(address(0), to, amount, mintedTokens_);
    }

    /// @inheritdoc IUsdn
    function rebase(
        uint256 newDivisor
    )
        external
        onlyRole(REBASER_ROLE)
        returns (
            bool rebased_,
            uint256 oldDivisor_,
            bytes memory callbackResult_
        )
    {
        oldDivisor_ = _divisor;
        if (newDivisor > oldDivisor_) {
            newDivisor = oldDivisor_;
        } else if (newDivisor < MIN_DIVISOR) {
            newDivisor = MIN_DIVISOR;
        }
        if (newDivisor == oldDivisor_) {
            return (false, oldDivisor_, callbackResult_);
        }

        _divisor = newDivisor;
        rebased_ = true;
        IRebaseCallback handler = _rebaseHandler;
        if (address(handler) != address(0)) {
            // Use a low-level call with a fixed gas stipend to protect against gas exhaustion
            (bool success, bytes memory result) = address(handler).call{
                gas: REBASE_CALLBACK_GAS_STIPEND
            }(
                abi.encodeWithSelector(
                    IRebaseCallback.rebaseCallback.selector,
                    oldDivisor_,
                    newDivisor
                )
            );

            if (success) {
                callbackResult_ = result;
            } else {
                // Either revert or OOG inside callback
                callbackResult_ = abi.encodePacked("Callback failed");
            }
        }
        emit Rebase(oldDivisor_, newDivisor);
    }

    /// @inheritdoc IUsdn
    function setRebaseHandler(
        IRebaseCallback newHandler
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _rebaseHandler = newHandler;
        emit RebaseHandlerUpdated(newHandler);
    }

    /* -------------------------------------------------------------------------- */
    /*                             Internal functions                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Converts an amount of shares into the corresponding amount of tokens, rounding the division according to
     * the specified direction.
     * @dev If rounding to the nearest integer and the result is exactly at the halfway point, we round up.
     * @param amountShares The amount of shares to convert to tokens.
     * @param rounding The rounding direction: down, closest, or up.
     * @param d The current divisor value used for the conversion.
     * @return tokens_ The calculated equivalent amount of tokens.
     */
    function _convertToTokens(
        uint256 amountShares,
        Rounding rounding,
        uint256 d
    ) internal pure returns (uint256 tokens_) {
        if (amountShares == 0) {
            return 0;
        }
        if (d == 0) {
            revert UsdnInvalidDivisor();
        }
        // Formula: tokens = shares / divisor
        if (rounding == Rounding.Down) {
            tokens_ = amountShares / d;
        } else if (rounding == Rounding.Up) {
            tokens_ = FixedPointMathLib.divUp(amountShares, d);
        } else {
            // When it is Rounding.Closest
            // Correct implementation for rounding to closest using FixedPointMathLib
            // Note: Solady's FixedPointMathLib might not have divDown, check library or use standard math
            // For simplicity, using standard math rounding:
            uint256 halfDivisor = d / 2;
            if (d % 2 == 1) {
                halfDivisor++; // Round half up for odd divisors
            }
            tokens_ = (amountShares + halfDivisor) / d;

            // If using Solady's divUp for closest rounding (rounds half up)
            // tokens_ = FixedPointMathLib.divUp(amountShares * 2 + d, d * 2);
        }
    }

    /**
     * @notice Converts an amount of tokens into the corresponding amount of shares.
     * @dev Given the decimal ratio is always going to be downwards, no rounding will be needed.
     * There are also checks to prevent calculations that result in values larger
     * than the maximum uint256 value.
     * @param amountTokens The amount of tokens to convert to shares.
     * @param d The current divisor value used for the conversion.
     * @return shares_ The calculated equivalent amount of shares.
     */
    function _convertToShares(
        uint256 amountTokens,
        Rounding /*rounding*/,
        uint256 d
    ) internal pure returns (uint256 shares_) {
        if (amountTokens == 0) {
            return 0;
        }
        if (d == 0) {
            revert UsdnInvalidDivisor();
        }
        if (amountTokens > type(uint256).max / d) {
            revert UsdnMaxTokensExceeded(amountTokens);
        }
        // Shares = tokens * divisor, this can never cause a rounding issue.
        shares_ = amountTokens * d;
    }

    /**
     * @notice Updates the share balances of the involved accounts.
     * @param from The account from which the shares are transferred, can be address(0) for minting.
     * @param to The account to which the shares are transferred, can be address(0) for burning.
     * @param shares The amount of shares being transferred.
     * @param tokens The corresponding token amount, used in the event.
     */
    function _updateShares(
        address from,
        address to,
        uint256 shares,
        uint256 tokens
    ) internal {
        if (from == address(0)) {
            // Mint operation
            _totalShares = _totalShares + shares; // Avoid potential overflow issues if shares is huge
        } else {
            // Transfer or Burn operation
            uint256 fromShares = _shares[from];
            if (fromShares < shares) {
                // Use the more specific error if available from IUsdnErrors
                revert UsdnInsufficientSharesBalance(from, fromShares, shares);
            }
            unchecked {
                _shares[from] = fromShares - shares;
            }
        }

        if (to == address(0)) {
            // Burn operation
            _totalShares = _totalShares - shares;
        } else {
            // Transfer or Mint operation
            _shares[to] = _shares[to] + shares;
        }

        emit Transfer(from, to, tokens);
    }

    /**
     * @notice Internal function to transfer shares from one account to another, updating the corresponding token totals.
     * @param from Address to transfer the shares from.
     * @param to Address to transfer the shares to.
     * @param shares Number of shares to transfer.
     * @param tokens Number of tokens the shares amount corresponds to.
     */
    function _transferShares(
        address from,
        address to,
        uint256 shares,
        uint256 tokens
    ) internal {
        if (from == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        _updateShares(from, to, shares, tokens);
    }

    /**
     * @notice Internal function to burn shares from an account, reducing both local and total share counts.
     * @param account Address to burn the shares from.
     * @param shares Amount of shares to burn.
     * @param tokens Amount of tokens the shares correspond to.
     */
    function _burnShares(
        address account,
        uint256 shares,
        uint256 tokens
    ) internal {
        if (account == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        _updateShares(account, address(0), shares, tokens);
    }

    /**
     * @dev Updates balances after transfers.
     * Hook that is called after increases or decreases in balances.
     *
     * @param from The transferring address.
     * @param to The receiving address.
     * @param amount The amount of shares transferred.
     */
    function _update(
        address from,
        address to,
        uint256 amount
    ) internal virtual override {
        // This override uses the token amount `amount` directly
        uint256 sharesAmount = _convertToShares(amount, Rounding.Up, _divisor);

        if (from == address(0)) {
            // Mint
            _totalShares += sharesAmount;
        } else {
            // Transfer / Burn
            uint256 fromShares = _shares[from];
            uint256 fromBalance = _convertToTokens(
                fromShares,
                Rounding.Down,
                _divisor
            );
            if (fromBalance < amount) {
                revert UsdnInsufficientBalance(from, amount, fromBalance);
            }
            // Adjust shares based on token amount burnt/sent. Rounding might require setting to 0.
            if (sharesAmount <= fromShares) {
                unchecked {
                    _shares[from] = fromShares - sharesAmount;
                }
            } else {
                // Not enough shares to cover token amount due to rounding -> burn all shares
                sharesAmount = fromShares; // Adjust actual shares transferred/burned
                _shares[from] = 0;
            }
        }

        if (to == address(0)) {
            // Burn
            _totalShares -= sharesAmount;
        } else {
            // Transfer / Mint
            _shares[to] += sharesAmount;
        }

        emit Transfer(from, to, amount);
    }
}
