// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

type param interface {
	marshal() ([]byte, error)
	length() int
}

// ErrParamTypeUnhandled is returned if unknown parameter type is specified.
var ErrParamTypeUnhandled = errors.New("unhandled ParamType")

func buildParam(typeParam paramType, rawParam []byte) (param, error) { //nolint:cyclop
	switch typeParam {
	case forwardTSNSupp:
		return (&paramForwardTSNSupported{}).unmarshal(rawParam)
	case supportedExt:
		return (&paramSupportedExtensions{}).unmarshal(rawParam)
	case ecnCapable:
		return (&paramECNCapable{}).unmarshal(rawParam)
	case random:
		return (&paramRandom{}).unmarshal(rawParam)
	case reqHMACAlgo:
		return (&paramRequestedHMACAlgorithm{}).unmarshal(rawParam)
	case chunkList:
		return (&paramChunkList{}).unmarshal(rawParam)
	case stateCookie:
		return (&paramStateCookie{}).unmarshal(rawParam)
	case heartbeatInfo:
		return (&paramHeartbeatInfo{}).unmarshal(rawParam)
	case outSSNResetReq:
		return (&paramOutgoingResetRequest{}).unmarshal(rawParam)
	case reconfigResp:
		return (&paramReconfigResponse{}).unmarshal(rawParam)
	case zeroChecksumAcceptable:
		return (&paramZeroChecksumAcceptable{}).unmarshal(rawParam)
	default:
		return nil, fmt.Errorf("%w: %v", ErrParamTypeUnhandled, typeParam)
	}
}
