# FOX Evidence JSON Schema v1

> Frozen at P0-1. All future GUI, AI, and reporting systems MUST consume this schema.
> GUI must NOT re-parse analysis results.

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "FOX AnalysisResult",
  "type": "object",
  "required": ["binary", "functions", "basic_blocks", "edges", "calls", "evidence"],
  "properties": {
    "binary": {
      "type": "object",
      "description": "Binary metadata",
      "properties": {
        "format": { "type": "string", "enum": ["PE32", "PE32Plus", "ELF32", "ELF64", "MachO32", "MachO64", "Unknown"] },
        "architecture": { "type": "string", "enum": ["X86", "X64", "ARM64", "Unknown"] },
        "entry_point": { "type": "string", "description": "Hex address" },
        "image_base": { "type": "string", "description": "Hex address" },
        "size": { "type": "integer" },
        "sections": { "type": "array", "items": { "$ref": "#/$defs/Section" } }
      }
    },
    "functions": {
      "type": "array",
      "description": "Discovered functions with confidence tiers",
      "items": { "$ref": "#/$defs/Function" }
    },
    "basic_blocks": {
      "type": "array",
      "description": "All basic blocks across all functions",
      "items": { "$ref": "#/$defs/BasicBlock" }
    },
    "edges": {
      "type": "array",
      "description": "All CFG edges with evidence",
      "items": { "$ref": "#/$defs/CfgEdge" }
    },
    "calls": {
      "type": "array",
      "description": "All call graph edges",
      "items": { "$ref": "#/$defs/CallEdge" }
    },
    "evidence": {
      "type": "object",
      "description": "Evidence index for traceability",
      "properties": {
        "instruction_evidence": { "type": "array", "items": { "$ref": "#/$defs/Evidence" } },
        "block_evidence": { "type": "array", "items": { "$ref": "#/$defs/Evidence" } },
        "function_evidence": { "type": "array", "items": { "$ref": "#/$defs/Evidence" } }
      }
    }
  },
  "$defs": {
    "Section": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "virtual_address": { "type": "string" },
        "virtual_size": { "type": "integer" },
        "raw_offset": { "type": "integer" },
        "raw_size": { "type": "integer" },
        "executable": { "type": "boolean" },
        "readable": { "type": "boolean" },
        "writable": { "type": "boolean" }
      }
    },
    "Function": {
      "type": "object",
      "required": ["name", "address", "confidence", "confidence_tier", "evidence"],
      "properties": {
        "name": { "type": "string" },
        "address": { "type": "string", "description": "Hex VA" },
        "end_address": { "type": ["string", "null"] },
        "size": { "type": ["integer", "null"] },
        "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
        "confidence_tier": { "type": "string", "enum": ["Confirmed", "High", "Probable", "Unknown"] },
        "evidence": { "type": "array", "items": { "$ref": "#/$defs/Evidence" } }
      }
    },
    "BasicBlock": {
      "type": "object",
      "required": ["id", "start_address", "end_address", "instructions", "successors"],
      "properties": {
        "id": { "type": "integer" },
        "function_address": { "type": "string" },
        "start_address": { "type": "string" },
        "end_address": { "type": "string" },
        "instruction_count": { "type": "integer" },
        "instructions": { "type": "array", "items": { "$ref": "#/$defs/Instruction" } },
        "successors": { "type": "array", "items": { "$ref": "#/$defs/CfgEdge" } },
        "predecessors": { "type": "array", "items": { "type": "integer" } }
      }
    },
    "Instruction": {
      "type": "object",
      "properties": {
        "address": { "type": "string" },
        "length": { "type": "integer" },
        "mnemonic": { "type": "string" },
        "operands": { "type": "string" },
        "raw_bytes": { "type": "array", "items": { "type": "integer" } },
        "is_call": { "type": "boolean" },
        "is_ret": { "type": "boolean" },
        "is_jump": { "type": "boolean" },
        "is_conditional_jump": { "type": "boolean" },
        "jump_target": { "type": ["string", "null"] },
        "call_target": { "type": ["string", "null"] }
      }
    },
    "CfgEdge": {
      "type": "object",
      "required": ["kind", "source_block", "evidence"],
      "properties": {
        "kind": { "type": "string", "enum": [
          "Fallthrough", "ConditionalTrue", "ConditionalFalse",
          "UnconditionalJump", "Call", "Return",
          "IndirectJump", "IndirectCall", "Unknown"
        ]},
        "source_block": { "type": "integer" },
        "target_block": { "type": ["integer", "null"] },
        "target_address": { "type": ["string", "null"] },
        "source_instruction": { "type": "string" },
        "evidence": { "type": "array", "items": { "$ref": "#/$defs/Evidence" } }
      }
    },
    "CallEdge": {
      "type": "object",
      "required": ["kind", "caller", "call_instruction", "evidence"],
      "properties": {
        "kind": { "type": "string", "enum": ["Direct", "Indirect", "External", "Unknown"] },
        "caller": { "type": "string" },
        "callee": { "type": ["string", "null"] },
        "call_instruction": { "type": "string" },
        "evidence": { "type": "array", "items": { "$ref": "#/$defs/Evidence" } }
      }
    },
    "Evidence": {
      "type": "object",
      "required": ["kind", "weight"],
      "properties": {
        "kind": { "type": "string", "description": "EvidenceKind enum value" },
        "weight": { "type": "number", "description": "Positive = supporting, Negative = contradicting" },
        "address": { "type": ["string", "null"] },
        "description": { "type": ["string", "null"] }
      }
    }
  }
}
```

## Evidence Chain

```
Instruction (address, opcode, operands)
    ↓ evidence: ValidInstructionDecoded
BasicBlock (start, end, instructions[])
    ↓ evidence: BlockTerminator { mnemonic }
CFG Edge (kind, source, target)
    ↓ evidence: ConditionalTrueEdge / FallthroughEdge / ...
Function (address, name, confidence)
    ↓ evidence: EntryPoint / ExportEntry / CallReference / FunctionPrologue
    ↓ negative evidence: NegativeNonExecutableSection / NegativeInvalidInstructionBoundary
```

## Confidence Aggregation

```
confidence = max_positive_weight + 0.1 * (n-1) * (1 - max_positive_weight) - sum(negative_weights)
```

- Single evidence NEVER reaches 1.0
- Negative evidence reduces confidence
- Confidence ≤ 0.05 → function discarded

## Confidence Tiers

| Tier      | Confidence | Meaning |
|-----------|-----------|---------|
| Confirmed | ≥ 0.85    | Entry point or export + reachable |
| High      | ≥ 0.65    | Export or ≥3 call references + valid prologue |
| Probable  | ≥ 0.40    | Single call reference or prologue match |
| Unknown   | < 0.40    | Weak single evidence |
