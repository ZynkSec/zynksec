/**
 * Vitest global setup — runs once before any test file.
 *
 * RTL's ``cleanup`` between each test was implicit in Jest +
 * @testing-library/react via the ``--testEnvironment=jsdom``
 * default; under Vitest we have to wire it explicitly.  Without
 * this, mounted components from a previous test stick around in
 * the DOM and ``screen.getBy*`` queries surface duplicates.
 */
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});
