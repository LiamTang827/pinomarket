// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import {BatchMarket, DirectMarket, Market} from "../src/Market.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address msgSender) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert(bytes calldata revertData) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter) external;
}

contract MarketTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant ALICE = address(0xa11ce);
    address private constant BOB = address(0xb0b);
    bytes32 private constant LOCK = keccak256("lock 1");

    DirectMarket private direct;
    BatchMarket private batch;

    event OrderSkipped(address indexed trader, uint256 indexed nonce, Market.SkipReason reason);

    function setUp() public {
        address[] memory traders = new address[](2);
        traders[0] = ALICE;
        traders[1] = BOB;
        address[] memory signers = new address[](3);
        for (uint256 i = 0; i < signers.length; ++i) {
            signers[i] = vm.addr(i + 1);
        }
        direct = new DirectMarket(traders);
        batch = new BatchMarket(traders, signers, 2);
    }

    function testDirectSwapRequiresFundsAndMinimumOutput() public {
        vm.prank(ALICE);
        uint256 amountOut = direct.swap(true, 100_000, 90_000);
        assert(amountOut == 90_909);

        vm.expectRevert(abi.encodeWithSelector(DirectMarket.InvalidSwap.selector, Market.SkipReason.InsufficientOutput));
        vm.prank(ALICE);
        direct.swap(true, 100_000, 90_000);

        vm.expectRevert(
            abi.encodeWithSelector(DirectMarket.InvalidSwap.selector, Market.SkipReason.InsufficientBalance)
        );
        vm.prank(BOB);
        direct.swap(false, 1, 0);

        assert(direct.reserveQuote() == 1_100_000);
        assert(direct.reserveAsset() == 909_091);
        assert(direct.assetBalance(ALICE) == 90_909);
    }

    function testBatchRejectsReorderAndOmissionThenExecutesSignedList() public {
        BatchMarket.Order[] memory orders = _twoBuys();
        bytes[] memory signatures = _sign(1, LOCK, orders);

        BatchMarket.Order[] memory reordered = new BatchMarket.Order[](2);
        reordered[0] = orders[1];
        reordered[1] = orders[0];
        vm.expectRevert(BatchMarket.InvalidSignatures.selector);
        batch.executeBatch(1, LOCK, reordered, signatures);

        BatchMarket.Order[] memory omitted = new BatchMarket.Order[](1);
        omitted[0] = orders[1];
        vm.expectRevert(BatchMarket.InvalidSignatures.selector);
        batch.executeBatch(1, LOCK, omitted, signatures);

        assert(batch.reserveQuote() == 1_000_000);
        assert(batch.nextBatch() == 1);
        batch.executeBatch(1, LOCK, orders, signatures);

        assert(batch.assetBalance(ALICE) == 90_909);
        assert(batch.assetBalance(BOB) == 75_757);
        assert(batch.nextBatch() == 2);
    }

    function testBatchRejectsInsufficientDuplicateAndUnknownSignatures() public {
        BatchMarket.Order[] memory orders = _twoBuys();
        bytes[] memory signatures = _sign(1, LOCK, orders);
        bytes[] memory insufficient = new bytes[](1);
        insufficient[0] = signatures[0];
        vm.expectRevert(BatchMarket.InvalidSignatures.selector);
        batch.executeBatch(1, LOCK, orders, insufficient);

        signatures[1] = signatures[0];
        vm.expectRevert(BatchMarket.InvalidSignatures.selector);
        batch.executeBatch(1, LOCK, orders, signatures);

        signatures[1] = _signOne(batch.batchDigest(1, LOCK, orders), 4);
        vm.expectRevert(BatchMarket.InvalidSignatures.selector);
        batch.executeBatch(1, LOCK, orders, signatures);
        assert(batch.nextBatch() == 1);
    }

    function testBatchRejectsReplayAndDirectSwap() public {
        BatchMarket.Order[] memory orders = _twoBuys();
        bytes[] memory signatures = _sign(1, LOCK, orders);
        batch.executeBatch(1, LOCK, orders, signatures);

        vm.expectRevert(BatchMarket.InvalidBatch.selector);
        batch.executeBatch(1, LOCK, orders, signatures);

        bytes[] memory reusedLockSignatures = _sign(2, LOCK, orders);
        vm.expectRevert(BatchMarket.InvalidBatch.selector);
        batch.executeBatch(2, LOCK, orders, reusedLockSignatures);

        vm.prank(ALICE);
        (bool success,) = address(batch).call(abi.encodeCall(DirectMarket.swap, (true, 100_000, 0)));
        assert(!success);
        assert(batch.assetBalance(ALICE) == 90_909);
    }

    function testBatchSkipsUnfundedOrderAndStaleNonceThenContinues() public {
        BatchMarket.Order[] memory orders = new BatchMarket.Order[](3);
        orders[0] = BatchMarket.Order(ALICE, true, 1_000_001, 0, 0);
        orders[1] = BatchMarket.Order(ALICE, true, 100_000, 0, 0);
        orders[2] = BatchMarket.Order(ALICE, true, 100_000, 0, 1);
        bytes[] memory signatures = _sign(1, LOCK, orders);

        vm.expectEmit(true, true, false, true, address(batch));
        emit OrderSkipped(ALICE, 0, Market.SkipReason.InsufficientBalance);
        vm.expectEmit(true, true, false, true, address(batch));
        emit OrderSkipped(ALICE, 0, Market.SkipReason.WrongNonce);
        batch.executeBatch(1, LOCK, orders, signatures);

        assert(batch.nextNonce(ALICE) == 2);
        assert(batch.assetBalance(ALICE) == 90_909);
        assert(batch.nextBatch() == 2);
    }

    function _twoBuys() private pure returns (BatchMarket.Order[] memory orders) {
        orders = new BatchMarket.Order[](2);
        orders[0] = BatchMarket.Order(ALICE, true, 100_000, 0, 0);
        orders[1] = BatchMarket.Order(BOB, true, 100_000, 0, 0);
    }

    function _sign(uint256 number, bytes32 lockId, BatchMarket.Order[] memory orders)
        private
        returns (bytes[] memory signatures)
    {
        bytes32 digest = batch.batchDigest(number, lockId, orders);
        signatures = new bytes[](2);
        signatures[0] = _signOne(digest, 1);
        signatures[1] = _signOne(digest, 2);
    }

    function _signOne(bytes32 digest, uint256 privateKey) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
