# TODO - Fix Blockers

## BLOCKER 1 - executor.py broken API
- [x] Create TODO file
- [ ] Revert executor.py to original working form with execute_attack() method
- [ ] Fix business_logic_attacker.py calls if needed

## BLOCKER 2 - Scope creep in attack_planner.py
- [ ] Remove _is_file_upload_endpoint() method
- [ ] Remove _plan_file_upload_attacks() method
- [ ] Remove _is_deserialization_endpoint() method
- [ ] Remove _plan_deserialization_attacks() method
- [ ] Remove _detect_deserialization_languages() method
- [ ] Remove _select_deserialization_payloads() method
- [ ] Remove calls to these methods in _plan_rule_based()

## BLOCKER 3 - cleanup_python.py
- [ ] Verify file status (not visible in root - likely already removed)
