# Authors & Attribution

## Concept & design

**Tony Maida** — originator of the MOSA Domain Overlay concept and design.

The idea this project implements is Tony Maida's: a **Domain Overlay** for MOSA —
a repeatable, model-based framework that integrates with Model-Based Systems
Engineering (MBSE) practices to assess and enforce MOSA compliance **without
altering the underlying systems**, applied as a non-disruptive, cross-cutting
overlay that can be added to or removed from an architecture description without
breaking it. The original design comprises:

1. Non-disruptive "overlay" application (add/remove without impacting the base architecture)
2. Reusable libraries (MOSA objectives, benefits, capabilities, resources) + tool-specific validation rules
3. A lightweight ontological framework, structured as a UAF-based project-assessment model pattern
4. Normalization of diverse artifacts (models, cost estimates, risk registers) into common views, with stakeholder-specific value algorithms
5. Guided workflows and fit-for-purpose dashboards per role (PEO / PM / capability owner / systems & test engineer)

## Provenance note

For attribution precision: the general UAF **"Domain Overlay" construct** has prior
public authorship — see Shearin & Wise (Georgia Tech Research Institute), OMG,
March 2023, *"How I Stumbled Across A Domain Overlay and Why It's Actually Useful"*
([OMG PDF](https://www.omg.org/uaf/resources/march-2023/How-I-Stumbled-Across-A-Domain-Overlay-and-Why-It-Actually-Useful-Shearin-Wise-Georgia-Tech-Research-Institute.pdf)).
The cleanest framing is therefore: **the MOSA Domain Overlay design is Tony
Maida's, building on the UAF domain-overlay construct.** If you have a precise
citation for Tony's MOSA-specific work, please open a PR to add it here.

## This implementation

This repository is an **independent open-source (Apache-2.0) implementation** of
Tony Maida's concept. It deliberately reduces the design to its most sustainable
form for adoption at scale — a **rules pack plus a lightweight manifest
("MOSA-BOM")** that any program can run in its own CI, rather than a centrally
operated platform. The reduction (and any divergence from the original design)
is an implementation choice of this project; the foundational concept remains
Tony Maida's.

Implementation contributors are listed via the project's git history.
