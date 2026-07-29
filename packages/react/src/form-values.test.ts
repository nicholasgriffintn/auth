import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { selectFormValues } from "./form-values.js";

describe("dynamic form values", () => {
  it("submits only fields present in the current challenge", () => {
    assert.deepEqual(
      selectFormValues(
        [{ name: "code", label: "Code", required: true }],
        {
          email: "person@example.com",
          password: "sensitive-password",
          code: "123456",
        }
      ),
      { code: "123456" }
    );
    assert.deepEqual(
      selectFormValues(
        [{ name: "remember", label: "Remember", type: "checkbox" }],
        {}
      ),
      { remember: false }
    );
  });
});
