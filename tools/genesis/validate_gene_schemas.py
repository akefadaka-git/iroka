#!/usr/bin/env python3
"""Fail-closed resolver and executable conformance runner for GENESIS gene IO."""
import json, sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[2]
GENOME=ROOT/"crates/iroka-kernel/igacms/genome-v1.0.0.json"
CONTRACTS=ROOT/"docs/architecture/GENESIS-GENE-IO-CONTRACT-AMENDMENT-A1-PROPOSAL-v1.0.0.json"
FIXTURES=ROOT/"crates/iroka-kernel/igacms/conformance/gene-io-v1.0.0.json"
def load(path):
 with path.open(encoding="utf-8") as f:return json.load(f)
def pointer(root,ref):
 if ref=="#":return root
 if not ref.startswith("#/"):raise ValueError("Only local JSON Pointer $refs are permitted: "+str(ref))
 node=root
 for token in ref[2:].split("/"):
  token=token.replace("~1","/").replace("~0","~")
  node=node[int(token)] if isinstance(node,list) else node[token]
 return node
def refs(node):
 if isinstance(node,dict):
  out=[node["$ref"]] if "$ref" in node else []
  for v in node.values():out.extend(refs(v))
  return out
 if isinstance(node,list):
  out=[]
  for v in node:out.extend(refs(v))
  return out
 return []
def check_ref_graph(schema):
 graph={}
 def collect(ref):
  if ref in graph:return
  target=pointer(schema,ref);graph[ref]=refs(target)
  for child in graph[ref]:
   if not isinstance(child,str) or not child.startswith("#"):raise ValueError("External $ref forbidden: "+str(child))
   collect(child)
 for ref in refs(schema):
  if not isinstance(ref,str) or not ref.startswith("#"):raise ValueError("External $ref forbidden: "+str(ref))
  collect(ref)
 active=set();done=set()
 def visit(ref):
  if ref in done:return
  if ref in active:raise ValueError("Cyclic internal $ref dependency: "+ref)
  active.add(ref)
  for child in graph.get(ref,[]):visit(child)
  active.remove(ref);done.add(ref)
 for ref in graph:visit(ref)
def main():
 proposal,genome,fixtures=load(CONTRACTS),load(GENOME),load(FIXTURES)
 if proposal.get("status")!="OWNER_APPROVED_NORMATIVE_BASELINE":raise ValueError("Gene contract amendment is not Owner-approved")
 contracts={x["gene_id"]:x for x in proposal["contracts"]};genes={x["id"]:x for x in genome["genes"]};cases={x["gene_id"]:x for x in fixtures["cases"]}
 if len(contracts)!=36 or len(genes)!=36 or len(cases)!=36 or set(contracts)!=set(genes) or set(contracts)!=set(cases):raise ValueError("Expected exactly 36 matching gene contracts, Genome genes and conformance cases")
 resolved=positive=negative=0
 for gid,gene in genes.items():
  contract,case=contracts[gid],cases[gid]
  if case["case_id"]!=contract["conformance"]["case_id"] or case["case_id"] not in gene["conformance_cases"]:raise ValueError("Conformance case ID mismatch: "+gid)
  for side in ("input","output"):
   spec=contract[side+"_contract"]
   if gene[side+"_schema"]!=spec["file_path"].replace("crates/iroka-kernel/igacms/",""):raise ValueError("Genome reference mismatch: "+gid+"/"+side)
   path=ROOT/spec["file_path"];schema=load(path)
   if schema.get("$id")!=spec["schema_id"] or schema.get("$schema")!=proposal["schema_convention"]["dialect"]:raise ValueError("Stable schema ID/dialect mismatch: "+str(path))
   if schema.get("type")!="object" or schema.get("additionalProperties") is not False:raise ValueError("Root object must be closed: "+str(path))
   if not set(spec["required"]).issubset(set(schema.get("required",[]))):raise ValueError("Required fields missing from schema: "+str(path))
   if not {"provenance","version_bound_evidence"}.issubset(set(schema.get("required",[]))):raise ValueError("Common evidence requirements missing: "+str(path))
   Draft202012Validator.check_schema(schema);check_ref_graph(schema)
   validator=Draft202012Validator(schema);vectors=case[side]
   if vectors["schema_path"]!=spec["file_path"]:raise ValueError("Fixture path mismatch: "+gid+"/"+side)
   if list(validator.iter_errors(vectors["positive"]["instance"])):raise ValueError("Positive vector rejected: "+gid+"/"+side)
   positive+=1
   if not list(validator.iter_errors(vectors["negative"]["instance"])):raise ValueError("Negative vector accepted: "+gid+"/"+side)
   negative+=1;resolved+=1
 if (resolved,positive,negative)!=(72,72,72):raise ValueError("Incomplete closure counts")
 print("PASS: all 72/72 Genome schema references resolve to gene-specific files")
 print("PASS: all schemas are valid Draft 2020-12 with stable IDs and closed object contracts")
 print("PASS: all internal $refs resolve; external refs and cycles rejected")
 print("PASS: 36 gene cases; 72 positive vectors accepted; 72 negative vectors rejected")
if __name__=="__main__":
 try:main()
 except Exception as exc:print("FAIL-CLOSED:",type(exc).__name__,str(exc),file=sys.stderr);sys.exit(1)
