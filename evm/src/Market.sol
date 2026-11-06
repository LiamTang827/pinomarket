// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

/// @dev A zero-fee, constant-product market with virtual balances for the experiment.
abstract contract Market {
    enum SkipReason {
        None,
        UnknownTrader,
        WrongNonce,
        ZeroInput,
        InsufficientBalance,
        InsufficientOutput
    }

    uint256 public reserveQuote = 1_000_000;
    uint256 public reserveAsset = 1_000_000;
    mapping(address => uint256) public quoteBalance;
    mapping(address => uint256) public assetBalance;
    mapping(address => bool) internal enrolled;

    error InvalidTrader();

    event Swapped(address indexed trader, bool buy, uint256 amountIn, uint256 amountOut);

    constructor(address[] memory traders) {
        for (uint256 i = 0; i < traders.length; ++i) {
            address trader = traders[i];
            if (trader == address(0) || enrolled[trader]) revert InvalidTrader();
            enrolled[trader] = true;
            quoteBalance[trader] = 1_000_000;
        }
    }

    function _swap(address trader, bool buy, uint256 amountIn, uint256 minOut)
        internal
        returns (uint256 amountOut, SkipReason reason)
    {
        if (!enrolled[trader]) return (0, SkipReason.UnknownTrader);
        if (amountIn == 0) return (0, SkipReason.ZeroInput);

        uint256 balanceIn = buy ? quoteBalance[trader] : assetBalance[trader];
        if (amountIn > balanceIn) return (0, SkipReason.InsufficientBalance);

        uint256 reserveIn = buy ? reserveQuote : reserveAsset;
        uint256 reserveOut = buy ? reserveAsset : reserveQuote;
        amountOut = reserveOut * amountIn / (reserveIn + amountIn);
        if (amountOut == 0 || amountOut < minOut) return (0, SkipReason.InsufficientOutput);

        if (buy) {
            quoteBalance[trader] -= amountIn;
            assetBalance[trader] += amountOut;
            reserveQuote += amountIn;
            reserveAsset -= amountOut;
        } else {
            assetBalance[trader] -= amountIn;
            quoteBalance[trader] += amountOut;
            reserveAsset += amountIn;
            reserveQuote -= amountOut;
        }
        emit Swapped(trader, buy, amountIn, amountOut);
        return (amountOut, SkipReason.None);
    }
}

contract DirectMarket is Market {
    error InvalidSwap(SkipReason reason);

    constructor(address[] memory traders) Market(traders) {}

    function swap(bool buy, uint256 amountIn, uint256 minOut) external returns (uint256) {
        (uint256 amountOut, SkipReason reason) = _swap(msg.sender, buy, amountIn, minOut);
        if (reason != SkipReason.None) revert InvalidSwap(reason);
        return amountOut;
    }
}

/// @dev The committee attests that the plaintext order list corresponds to the
/// off-chain lock. This contract verifies that attestation and enforces execution
/// order. It does not verify how orders were received, sorted, or decrypted.
contract BatchMarket is Market {
    struct Order {
        address trader;
        bool buy;
        uint256 amountIn;
        uint256 minOut;
        uint256 nonce;
    }

    uint256 private constant MAX_SIGNATURE_S = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    uint256 public immutable threshold;
    uint256 public nextBatch = 1;
    mapping(address => uint256) public nextNonce;
    mapping(bytes32 => bool) public executedLock;

    // The one-based signer index lets us detect duplicates with a single bitmap.
    mapping(address => uint256) private signerIndex;
    uint256 private immutable signerCount;

    error InvalidCommittee();
    error InvalidBatch();
    error InvalidSignatures();

    event OrderSkipped(address indexed trader, uint256 indexed nonce, SkipReason reason);
    event BatchExecuted(uint256 indexed number, bytes32 indexed lockId);

    constructor(address[] memory traders, address[] memory signers, uint256 required) Market(traders) {
        if (required == 0 || required > signers.length || signers.length > 256) revert InvalidCommittee();
        threshold = required;
        signerCount = signers.length;
        for (uint256 i = 0; i < signers.length; ++i) {
            address signer = signers[i];
            if (signer == address(0) || signerIndex[signer] != 0) revert InvalidCommittee();
            signerIndex[signer] = i + 1;
        }
    }

    function batchDigest(uint256 number, bytes32 lockId, Order[] calldata orders) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), number, lockId, keccak256(abi.encode(orders))));
    }

    function executeBatch(uint256 number, bytes32 lockId, Order[] calldata orders, bytes[] calldata signatures)
        external
    {
        if (number != nextBatch || lockId == bytes32(0) || executedLock[lockId] || orders.length == 0) {
            revert InvalidBatch();
        }
        _verifySignatures(batchDigest(number, lockId, orders), signatures);

        nextBatch = number + 1;
        executedLock[lockId] = true;
        for (uint256 i = 0; i < orders.length; ++i) {
            Order calldata order = orders[i];
            SkipReason reason;
            if (!enrolled[order.trader]) {
                reason = SkipReason.UnknownTrader;
            } else if (order.nonce != nextNonce[order.trader]) {
                reason = SkipReason.WrongNonce;
            } else {
                // A valid nonce is consumed even if the swap fails a market rule.
                nextNonce[order.trader] = order.nonce + 1;
                (, reason) = _swap(order.trader, order.buy, order.amountIn, order.minOut);
            }
            if (reason != SkipReason.None) emit OrderSkipped(order.trader, order.nonce, reason);
        }
        emit BatchExecuted(number, lockId);
    }

    function _verifySignatures(bytes32 digest, bytes[] calldata signatures) private view {
        if (signatures.length < threshold || signatures.length > signerCount) revert InvalidSignatures();

        uint256 seen;
        for (uint256 i = 0; i < signatures.length; ++i) {
            uint256 index = signerIndex[_recover(digest, signatures[i])];
            if (index == 0) revert InvalidSignatures();
            uint256 bit = uint256(1) << (index - 1);
            if ((seen & bit) != 0) revert InvalidSignatures();
            seen |= bit;
        }
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert InvalidSignatures();
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (v < 2) v += 27;
        if ((v != 27 && v != 28) || uint256(s) > MAX_SIGNATURE_S) revert InvalidSignatures();
        return ecrecover(digest, v, r, s);
    }
}
