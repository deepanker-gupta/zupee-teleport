/*
Copyright 2022 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keys

import (
	"strings"

	"github.com/gravitational/trace"
)

// PrivateKeyPolicy is the mode required for client private key storage.
type PrivateKeyPolicy int

const (
	// PrivateKeyPolicyNone means that the client can store their private keys
	// anywhere (usually on disk).
	PrivateKeyPolicyNone PrivateKeyPolicy = iota
	// PrivateKeyPolicyHardwareKey means that the client must use a valid
	// hardware key to generate and store their private keys securely.
	PrivateKeyPolicyHardwareKey
	// PrivateKeyPolicyHardwareKeyTouch means that the client must use a valid
	// hardware key to generate and store their private keys securely, and
	// this key must require touch to be accessed and used.
	PrivateKeyPolicyHardwareKeyTouch

	privateKeyPolicyNoneString             = "none"
	privateKeyPolicyHardwareKeyString      = "hardware_key"
	privateKeyPolicyHardwareKeyTouchString = "hardware_key_touch"
)

// ParsePrivateKeyPolicy parses a private key policy from it's string representation.
func ParsePrivateKeyPolicy(policyString string) (PrivateKeyPolicy, error) {
	switch policyString {
	case privateKeyPolicyNoneString:
		return PrivateKeyPolicyNone, nil
	case privateKeyPolicyHardwareKeyString:
		return PrivateKeyPolicyHardwareKey, nil
	case privateKeyPolicyHardwareKeyTouchString:
		return PrivateKeyPolicyHardwareKeyTouch, nil
	default:
		return 0, trace.BadParameter("%q is not a valid key policy", policyString)
	}
}

// String converts the private key policy to a readable string.
func (p PrivateKeyPolicy) String() string {
	switch p {
	default:
		fallthrough
	case PrivateKeyPolicyNone:
		return privateKeyPolicyNoneString
	case PrivateKeyPolicyHardwareKey:
		return privateKeyPolicyHardwareKeyString
	case PrivateKeyPolicyHardwareKeyTouch:
		return privateKeyPolicyHardwareKeyTouchString
	}
}

// VerifyPolicy verifies that the given policy meets the requirements of this policy.
// If not, it will return a private key policy error, which can be parsed to retrive
// the unmet policy.
func (p PrivateKeyPolicy) VerifyPolicy(policy PrivateKeyPolicy) error {
	if p > policy {
		return newPrivateKeyPolicyError(p)
	}
	return nil
}

var privateKeyPolicyErrMsg = "private key policy not met: "

func newPrivateKeyPolicyError(p PrivateKeyPolicy) error {
	return trace.BadParameter(privateKeyPolicyErrMsg + p.String())
}

// IsPrivateKeyPolicyError returns whether this error is a private key policy
// error, in the form "private key policy not met: unmet-policy".
func IsPrivateKeyPolicyError(err error) bool {
	if trace.IsBadParameter(err) {
		return strings.Contains(err.Error(), privateKeyPolicyErrMsg)
	}
	return false
}

// ParsePrivateKeyPolicyError checks if the given error is a private key policy
// error and returns the contained PrivateKeyPolicy.
func ParsePrivateKeyPolicyError(err error) (PrivateKeyPolicy, error) {
	if !IsPrivateKeyPolicyError(err) {
		return 0, trace.BadParameter("provided error is not a key policy error")
	}

	policyStr := strings.ReplaceAll(err.Error(), privateKeyPolicyErrMsg, "")
	policy, err := ParsePrivateKeyPolicy(policyStr)
	if err != nil {
		return 0, trace.Wrap(err)
	}

	return policy, nil
}
