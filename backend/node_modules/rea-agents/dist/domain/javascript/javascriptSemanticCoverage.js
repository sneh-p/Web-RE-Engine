import { SEMANTIC_EXPRESSION_DEPTH_LIMIT, SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT, SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT, } from "./javascriptSemanticResourceLimits.js";
/** Classify whole-file semantic coverage from parsing and value bounds. */
export const semanticCoverage = (parserPartial, resourceLimits = []) => resourceLimits.length > 0
    ? { status: "partial", omittedCount: null, resourceLimits }
    : { status: parserPartial ? "partial" : "complete", omittedCount: 0 };
/** Read typed resource-limit classifications from any coverage state. */
export const semanticCoverageResourceLimits = (coverage) => coverage.resourceLimits ?? [];
const semanticResourceBounds = {
    "primitive-candidates": {
        value: SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT,
        unit: "items",
    },
    "primitive-bytes": {
        value: SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT,
        unit: "bytes",
    },
    "expression-depth": {
        value: SEMANTIC_EXPRESSION_DEPTH_LIMIT,
        unit: "depth",
    },
};
/** Map semantic evaluator bounds to their caller-visible application coverage. */
export const semanticResourceLimitCoverage = (resourceLimits) => resourceLimits.map((resourceLimit) => ({
    name: `javascript_semantic_${resourceLimit.replaceAll("-", "_")}`,
    ...semanticResourceBounds[resourceLimit],
}));
/** Classify one callable's direct-return coverage. */
export const semanticReturnCoverage = (retainedCount, parserPartial) => ({
    status: parserPartial ? "partial" : "complete",
    retainedCount,
    omittedCount: 0,
});
