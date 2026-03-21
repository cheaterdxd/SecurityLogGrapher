# ThreatGraph-MVP - Build Plan

## Phase 1: Project Setup
- [x] Initialize Python project structure
- [x] Create `requirements.txt`
- [x] Create conda environment (`threatgraph`) & install dependencies

## Phase 2: EVTX Parser Module
- [x] Implement `threatgraph/parser/evtx_parser.py`

## Phase 3: Event Normalizer Module
- [x] Implement `threatgraph/normalize/event_4688.py`
- [x] Write unit tests for normalizer (6 tests)

## Phase 4: Graph Builder Module
- [x] Implement `threatgraph/graph/builder.py`
- [x] Write unit tests for graph builder (9 tests)

## Phase 5: Visualization Module
- [x] Implement `threatgraph/visualize/pyvis_render.py`

## Phase 6: CLI Entry Point
- [x] Implement `threatgraph/main.py` with Typer
- [x] End-to-end integration test (2 tests)

## Phase 7: Verification
- [x] Run all unit tests — **22 passed ✅**
- [ ] Test with real `.evtx` file (cần user cung cấp)
