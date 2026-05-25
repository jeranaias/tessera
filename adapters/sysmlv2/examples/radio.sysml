// Illustrative SysML v2 (textual) model of a software-defined radio.
// Tessera's sysml2bom adapter DERIVES a MOSA-BOM from this model — the facts come
// from the engineering model, not a hand-written claim. This is the difference
// between attestation and verification (see ../../../docs/VIABILITY.md).
package RadioModel {

    @Program {
        id = "PRG-SDR-001";
        name = "Example Modular SDR";
        milestone = "MS-B";
    }

    part def Module;
    interface def KeyInterface;

    part radio {
        part rf : Module {
            @MOSA { severability = "severable"; supplier = "VendorA"; cost = 300000; }
        }
        part waveform : Module {
            @MOSA { severability = "severable"; supplier = "VendorB"; }
        }
        part control : Module {
            @MOSA { severability = "severable"; supplier = "VendorA"; }
        }
        part crypto : Module {
            @MOSA {
                severability = "non-severable"; supplier = "GovGFE";
                cost = 1200000; riskLikelihood = 4; riskConsequence = 5;
            }
        }

        connection ifRfWf : KeyInterface connect rf to waveform {
            @MOSA { key = true; standards = "MORA,REDHAWK"; documented = true; }
        }
        connection ifWfCtrl : KeyInterface connect waveform to control {
            @MOSA { key = true; standards = "DDS-1.4"; documented = true; }
        }
        // A KEY interface running on a proprietary bus — the model says so, and the
        // derived manifest will reflect it, so Tessera's gate catches it.
        connection ifCtrlCrypto : KeyInterface connect control to crypto {
            @MOSA { key = true; standards = "VENDOR-PROPRIETARY-BUS"; documented = false; }
        }
        connection ifInternal connect control to rf {
            @MOSA { key = false; }
        }
    }

    // MOSA objectives this program asserts, traced to the elements that realize them.
    @MOSAObjective { id = "OBJ-MODULAR-DESIGN"; tracesTo = "rf,waveform,control"; }
    @MOSAObjective { id = "OBJ-OPEN-STANDARDS"; tracesTo = "ifRfWf,ifWfCtrl"; }

    // Conformance requirements (feed the conformance-verified metric).
    requirement reqFaceConformance {
        @MOSA { conformance = "verified"; tracesTo = "ifRfWf"; }
    }
    requirement reqDdsConformance {
        @MOSA { conformance = "planned"; tracesTo = "ifWfCtrl"; }
    }
}
