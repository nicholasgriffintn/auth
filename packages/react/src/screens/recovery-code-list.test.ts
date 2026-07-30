import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Children,
  isValidElement,
  type ReactNode,
} from "react";

import { resolveConfig, uiConfig } from "../config.js";
import type { AuthClientChallenge } from "../types.js";
import {
  TotpSetupContent,
} from "./challenge-content.js";
import {
  RecoveryCodeActions,
  RecoveryCodeList,
} from "./recovery-code-list.js";

const config = uiConfig(resolveConfig({}));

describe("recovery code presentation", () => {
  it("uses the shared recovery-code UI during TOTP setup", () => {
    const challenge: AuthClientChallenge = {
      kind: "mfa_setup",
      continuationToken: "challenge-token",
      expiresAt: "2026-07-30T12:00:00.000Z",
      parameters: {
        secret: "SECRET",
        recoveryCodes: ["first-code", "second-code"],
      },
    };

    const content = TotpSetupContent({ challenge, config });
    const recoveryCodeList = Children.toArray(content.props.children).find(
      (child) => isValidElement(child) && child.type === RecoveryCodeList
    );

    assert.ok(
      isValidElement<{ readonly codes: readonly string[] }>(recoveryCodeList)
    );
    assert.deepEqual(recoveryCodeList.props.codes, [
      "first-code",
      "second-code",
    ]);
  });

  it("provides copy and download actions", () => {
    const actions = RecoveryCodeActions({
      codes: ["first-code"],
      config,
      onCopy() {},
    });
    const labels = Children.toArray(actions.props.children).map((child) => {
      assert.ok(
        isValidElement<{ readonly children?: ReactNode }>(child)
      );
      return child.props.children;
    });

    assert.deepEqual(labels, [
      config.copy.recoveryCodesCopyLabel,
      config.copy.recoveryCodesDownloadLabel,
    ]);
  });
});
