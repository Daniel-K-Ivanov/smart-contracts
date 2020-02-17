pragma solidity 0.5.11;

import "./BytesLib.sol";
import "./UtilsV5.sol";
import "./IKyberHint.sol";
import "./IKyberReserve.sol";


contract KyberHintHandler is IKyberHint, Utils {
    bytes public constant SEPARATOR_OPCODE = "\x00";
    bytes public constant MASK_IN_OPCODE = "\x01";
    bytes public constant MASK_OUT_OPCODE = "\x02";
    bytes public constant SPLIT_TRADE_OPCODE = "\x03";
    bytes public constant END_OPCODE = "\xee";
    bytes32 public constant SEPARATOR_KECCAK = keccak256(SEPARATOR_OPCODE);
    bytes32 public constant MASK_IN_KECCAK = keccak256(MASK_IN_OPCODE);
    bytes32 public constant MASK_OUT_KECCAK = keccak256(MASK_OUT_OPCODE);
    bytes32 public constant SPLIT_TRADE_KECCAK = keccak256(SPLIT_TRADE_OPCODE);
    bytes32 public constant END_KECCAK = keccak256(END_OPCODE);
    uint8 public constant RESERVE_ID_LENGTH = 8;

    using BytesLib for bytes;

    struct ReservesHint {
        TradeType tradeType;
        IKyberReserve[] addresses;
        bytes8[] ids;
        uint[] splitValuesBps;
    }

    struct TradeHint {
        ReservesHint e2t;
        ReservesHint t2e;
    }

    function parseHintE2T(bytes memory hint, ReservesHint memory reserveHint)
        internal
        view
    {
        uint indexToContinueFrom;
        TradeHint memory tradeHint;

        decodeOperation(hint, reserveHint, tradeHint, indexToContinueFrom);
    }

    function parseHintT2E(bytes memory hint, ReservesHint memory reserveHint)
        internal
        view
    {
        uint indexToContinueFrom;
        TradeHint memory tradeHint;

        decodeOperation(hint, reserveHint, tradeHint, indexToContinueFrom);
    }

    function parseHintT2T(bytes memory hint, TradeHint memory tradeHint)
        internal
        view
    {
        uint indexToContinueFrom;

        decodeOperation(hint, tradeHint.t2e, tradeHint, indexToContinueFrom);
    }

    function buildEthToTokenHint(
        TradeType ethToTokenType,
        bytes8[] memory ethToTokenReserveIds,
        uint[] memory ethToTokenSplits
    )
        public
        pure
        returns(bytes memory hint)
    {
        hint = hint.concat(SEPARATOR_OPCODE);
        hint = hint.concat(encodeReserveInfo(ethToTokenType, ethToTokenReserveIds, ethToTokenSplits));
        hint = hint.concat(END_OPCODE);
    }

    function buildTokenToEthHint(
        TradeType tokenToEthType,
        bytes8[] memory tokenToEthReserveIds,
        uint[] memory tokenToEthSplits
    )
        public
        pure
        returns(bytes memory hint)
    {
        hint = hint.concat(encodeReserveInfo(tokenToEthType, tokenToEthReserveIds, tokenToEthSplits));
        hint = hint.concat(SEPARATOR_OPCODE);
        hint = hint.concat(END_OPCODE);
    }

    function buildTokenToTokenHint(
        TradeType tokenToEthType,
        bytes8[] memory tokenToEthReserveIds,
        uint[] memory tokenToEthSplits,
        TradeType ethToTokenType,
        bytes8[] memory ethToTokenReserveIds,
        uint[] memory ethToTokenSplits
    )
        public
        pure
        returns(bytes memory hint)
    {
        hint = hint.concat(encodeReserveInfo(tokenToEthType, tokenToEthReserveIds, tokenToEthSplits));
        hint = hint.concat(SEPARATOR_OPCODE);
        hint = hint.concat(encodeReserveInfo(ethToTokenType, ethToTokenReserveIds, ethToTokenSplits));
        hint = hint.concat(END_OPCODE);
    }

    function encodeReserveInfo(
        TradeType opcode,
        bytes8[] memory reserveIds,
        uint[] memory bps
    )
        internal
        pure
        returns (bytes memory hint)
    {
        uint bpsSoFar;
        if (reserveIds.length > 0) {
            hint = hint.concat(encodeOpcode(opcode));
            hint = hint.concat(abi.encodePacked(uint8(reserveIds.length)));
            for (uint i = 0; i < reserveIds.length; i++) {
                hint = hint.concat(abi.encodePacked(reserveIds[i]));
                if (keccak256(encodeOpcode(opcode)) == keccak256(encodeOpcode(TradeType.Split))) {
                    hint = hint.concat(abi.encodePacked(uint16(bps[i])));
                    bpsSoFar += bps[i];
                }
            }
            require((bpsSoFar == BPS) || (bpsSoFar == 0), "BPS > 10000");
        }
    }

    function decodeOperation(
        bytes memory hint,
        ReservesHint memory resHint,
        TradeHint memory tradeHint,
        uint indexToContinueFrom
    )
        internal
        view
    {
        bytes memory opcode = hint.slice(indexToContinueFrom, 1);
        bytes32 opcodeKeccak = keccak256(opcode);
        
        indexToContinueFrom += 1;

        if (opcodeKeccak == END_KECCAK) {
            return;
        } else if (opcodeKeccak == SEPARATOR_KECCAK) {
            decodeOperation(hint, tradeHint.e2t, tradeHint, indexToContinueFrom);
        } else if (opcodeKeccak == MASK_IN_KECCAK) {
            resHint.tradeType = TradeType.MaskIn;
            (indexToContinueFrom) = decodeReservesFromHint(false, hint, resHint, indexToContinueFrom);
            decodeOperation(hint, resHint, tradeHint, indexToContinueFrom);
        } else if (opcodeKeccak == MASK_OUT_KECCAK) {
            resHint.tradeType = TradeType.MaskOut;
            (indexToContinueFrom) = decodeReservesFromHint(false, hint, resHint, indexToContinueFrom);
            decodeOperation(hint, resHint, tradeHint, indexToContinueFrom);
        } else if (opcodeKeccak == SPLIT_TRADE_KECCAK) {
            resHint.tradeType = TradeType.Split;
            (indexToContinueFrom) = decodeReservesFromHint(true, hint, resHint, indexToContinueFrom);
            decodeOperation(hint, resHint, tradeHint, indexToContinueFrom);
        } else {
            revert("Invalid hint opcode");
        }
    }

    function decodeReservesFromHint(
        bool isSplitTrade,
        bytes memory hint,
        ReservesHint memory reservesHint,
        uint indexToContinueFrom
    )
        internal
        view
        returns (
            uint
        )
    {
       uint bpsSoFar;
       uint reservesLength = hint.toUint8(indexToContinueFrom);
       reservesHint.addresses = new IKyberReserve[](reservesLength);

       if (isSplitTrade) {
           reservesHint.splitValuesBps = new uint[](reservesLength);
           reservesHint.ids = new bytes8[](reservesLength);
       } else {
           reservesHint.splitValuesBps = new uint[](1);
           reservesHint.splitValuesBps[0] = BPS;
       }

       indexToContinueFrom++;      

       for (uint i = 0; i < reservesLength; i++) {
           bytes8 id = hint.slice(indexToContinueFrom, RESERVE_ID_LENGTH).toBytes8(0);
           reservesHint.addresses[i] = IKyberReserve(convertReserveIdToAddress(id));

           indexToContinueFrom += RESERVE_ID_LENGTH;

           if (isSplitTrade) {
               reservesHint.ids[i] = id;
               reservesHint.splitValuesBps[i] = uint(hint.toUint16(indexToContinueFrom));
               bpsSoFar += reservesHint.splitValuesBps[i];
               indexToContinueFrom += 2;
           }
       }

       require((bpsSoFar == BPS) || (bpsSoFar == 0), "BPS > 10000");

       return indexToContinueFrom;
    }

    function encodeOpcode(TradeType tradeType) internal pure returns (bytes memory) {
        if (tradeType == TradeType.MaskIn) {
            return MASK_IN_OPCODE;
        } else if (tradeType == TradeType.MaskOut) {
            return MASK_OUT_OPCODE;
        } else if (tradeType == TradeType.Split) {
            return SPLIT_TRADE_OPCODE;
        }
    }

    function parseEthToTokenHint(bytes calldata hint)
        external
        view
        returns(
            TradeType ethToTokenType,
            bytes8[] memory ethToTokenReserveIds,
            uint[] memory ethToTokenSplits
        )
    {
        IKyberReserve[] memory ethToTokenAddresses;

        ReservesHint memory resHint;
        parseHintE2T(hint, resHint);

        ethToTokenReserveIds = new bytes8[](resHint.addresses.length);

        for (uint i = 0; i < ethToTokenAddresses.length; i++) {
            ethToTokenReserveIds[i] = convertAddressToReserveId(address(resHint.addresses[i]));
        }

        return (resHint.tradeType, ethToTokenReserveIds, resHint.splitValuesBps);
    }
        
    function parseTokenToEthHint(bytes calldata hint)
        external
        view
        returns(
            TradeType tokenToEthType,
            bytes8[] memory tokenToEthReserveIds,
            uint[] memory tokenToEthSplits
        )
    {
        ReservesHint memory resHint;
        parseHintT2E(hint, resHint);

        tokenToEthReserveIds = new bytes8[](resHint.addresses.length);

        for (uint i = 0; i < resHint.addresses.length; i++) {
            tokenToEthReserveIds[i] = convertAddressToReserveId(address(resHint.addresses[i]));
        }

        return(resHint.tradeType, tokenToEthReserveIds, resHint.splitValuesBps);
    }

    function parseTokenToTokenHint(bytes calldata hint)
        external
        view
        returns(
            TradeType tokenToEthType,
            bytes8[] memory tokenToEthReserveIds,
            uint[] memory tokenToEthSplits,
            TradeType ethToTokenType,
            bytes8[] memory ethToTokenReserveIds,
            uint[] memory ethToTokenSplits
        )
    {
        TradeHint memory tHint;

        parseHintT2T(hint, tHint);

        tokenToEthReserveIds = new bytes8[](tHint.t2e.addresses.length);
        ethToTokenReserveIds = new bytes8[](tHint.e2t.addresses.length);

        for (uint i = 0; i < tHint.t2e.addresses.length; i++) {
            tokenToEthReserveIds[i] = convertAddressToReserveId(address(tHint.t2e.addresses[i]));
        }
        for (uint i = 0; i < tHint.e2t.addresses.length; i++) {
            ethToTokenReserveIds[i] = convertAddressToReserveId(address(tHint.e2t.addresses[i]));
        }

        return(tHint.t2e.tradeType, tokenToEthReserveIds, tHint.t2e.splitValuesBps, tHint.e2t.tradeType, 
            ethToTokenReserveIds, tHint.e2t.splitValuesBps);
    }

    function convertReserveIdToAddress(bytes8 reserveId) internal view returns (address);
    function convertAddressToReserveId(address reserveAddress) internal view returns (bytes8);
}
