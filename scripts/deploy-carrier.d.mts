export declare const CARRIER: {
  commit: string;
  sourceDigest: string;
  branch: string;
  worker: string;
  databaseId: string;
  liveVersion: string;
  ownFiles: string[];
};
export declare function sourceDigest(lsTree: string): string;
export declare function configProblems(config: Record<string, unknown>): string[];
export declare function bundleProblems(source: string): string[];
export declare function liveProblems(status: unknown): string[];
