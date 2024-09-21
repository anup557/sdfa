# Code for the paper "[More Vulnerabilities of Linear Structure Sbox-Based Ciphers Reveal Their Inability to Protect DFA]"

This repository contains the implementations of the attacks presented in our paper:


# Usage

* Install dependencies
```bash
sudo apt install python3
```

```run
python3 $(PROGRAM_NAME)


# Mapping of Paper Section to Scripts

## Subsection 3.1 - Attacks on Simple Key Schedule

* Subsubsection 3.1.2 - Faults at the Second-to-Last Round
See `default/simple_key_schedule/attack_2_rounds/key_recovery.py`.

* Subsubsection 3.1.3 - Faults at the Third-to-Last Round
paragraph - Deterministic Trail Finding
See `default/simple_key_schedule/attack_3_rounds/finding_trail.py`.
paragraph - Key Recovery
See `default/simple_key_schedule/attack_3_rounds/key_recovery.py`.

* Subsubsection 3.1.4 - Faults at the Fourth-to-Last Round
paragraph - Deterministic Trail Finding
See `default/simple_key_schedule/attack_4_rounds/finding_trail.py`.
paragraph - Key Recovery
See `default/simple_key_schedule/attack_4_rounds/key_recovery.py`.

* Subsubsection 3.1.5 - Faults at the Fifth-to-Last Round
paragraph - Deterministic Trail Finding
See `default/simple_key_schedule/attack_5_rounds/finding_trail.py`.
paragraph - Key Recovery
See `default/simple_key_schedule/attack_5_rounds/key_recovery.py`.


## Subsection 3.2 - Attacks on Rotating Key Schedule

* Subsubsection 3.2.1 - Exploiting Equivalent Keys
See `default/rotating_key_schedule/find_normalized_key_schedule/finding_eq_keyspace.py`.

* Subsubsection 3.3 - Experimental Results on DEFAULT under DFA
for 3 rounds - See `default/rotating_key_schedule/attack_3_rounds/key_recovery_attack.py`.
for 4 rounds - See `default/rotating_key_schedule/attack_4_rounds/key_recovery_attack.py`.
for 5 rounds - See `default/rotating_key_schedule/attack_5_rounds/key_recovery_attack.py`.


# Section 4 - Introducing SDFA
* Subsubsection 4.5 - Experimental Results on DEFAULT under SDFA
See `default/sdfa/key_recovery.py`.

# Section 5 - Attacks on BAKSHEESH
* Subsubsection 5.3 - Experimental Results on BAKSHEESH
for 2 rounds - See `baksheesh/attack_2_rounds/key_recovery.py`.
for 3 rounds - See `baksheesh/attack_3_rounds/key_recovery.py`.
for sdfa - See `baksheesh/sdfa/key_recovery.py`.
