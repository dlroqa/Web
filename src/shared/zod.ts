/**
 * The project's single Zod entry point.
 *
 * `jitless` stops Zod from probing `new Function`, which the Workers runtime
 * forbids and which a strict browser CSP (no 'unsafe-eval') would report as a
 * violation. Import `z` from here, never from "zod" directly.
 */
import { z } from "zod";

z.config({ jitless: true });

export { z };
