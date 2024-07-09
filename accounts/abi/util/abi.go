package util

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

var functionRegex = regexp.MustCompile(`(?:function\s+)?(\w+)\s*\((.*?)\)\s*(?:returns\s*\((.*?)\))?`)
var paramsRegex = regexp.MustCompile(`([^\s,]+)\s+([^\s,]+)`)

// example humanReadable: swapTokensForExactBNB(uint256 amountOut, uint256 amountInMax, address[] path, address to, uint256 deadline)
func ParseFunction(humanReadable string) (sig string, in, out abi.Arguments, err error) {

	matches := functionRegex.FindAllStringSubmatch(humanReadable, -1)
	if len(matches) == 0 {
		err = fmt.Errorf("no matches found")
		return
	}
	if len(matches) > 1 {
		err = fmt.Errorf("too many matches found")
		return
	}
	match := matches[0]

	funcName := strings.TrimSpace(match[1])
	inArgs := strings.TrimSpace(match[2])
	var outArgs string
	if len(match) == 4 {
		outArgs = strings.TrimSpace(match[3])
	}

	in, err = parseArgs(inArgs)
	if err != nil {
		return
	}
	out, err = parseArgs(outArgs)
	if err != nil {
		return
	}

	var types []string
	for _, arg := range in {
		types = append(types, arg.Type.String())
	}

	sig = funcName + "(" + strings.Join(types, ",") + ")"
	return
}

func ParseFunctionsAsABI(humanReadables []string) (ab abi.ABI, err error) {
	ab.Methods = make(map[string]abi.Method)

	for _, humanReadable := range humanReadables {
		var (
			sig     string
			in, out abi.Arguments
		)
		sig, in, out, err = ParseFunction(humanReadable)
		if err != nil {
			return
		}
		method := SigToMethod(sig)

		ab.Methods[method] = abi.NewMethod(method, method, abi.Function, "", false, false, in, out)
	}
	return
}

func SigToMethod(sig string) string {
	idx := strings.Index(sig, "(")
	if idx == -1 {
		return sig
	}

	return sig[0:idx]
}

func parseArgs(arg string) (args abi.Arguments, err error) {
	if arg == "" {
		return
	}

	matches := paramsRegex.FindAllStringSubmatch(arg, -1)
	if len(matches) == 0 {
		return
	}

	for _, match := range matches {
		ty := match[1]
		if ty == "uint" {
			ty = "uint256"
		}
		var abiTy abi.Type
		abiTy, err = abi.NewType(ty, "", nil)
		if err != nil {
			return
		}
		name := match[2]
		args = append(args, abi.Argument{Name: name, Type: abiTy})
	}
	return
}
