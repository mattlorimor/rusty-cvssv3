const ATTACK_VECTOR_NOTDEFINED_WEIGHT: f32 = 1.0;
const ATTACK_VECTOR_NETWORK_WEIGHT: f32 = 0.85;
const ATTACK_VECTOR_ADJACENT_WEIGHT: f32 = 0.62;
const ATTACK_VECTOR_LOCAL_WEIGHT: f32 = 0.55;
const ATTACK_VECTOR_PHYSICAL_WEIGHT: f32 = 0.2;
const ATTACK_VECTOR_NOTDEFINED_LETTER: &'static str = "X";
const ATTACK_VECTOR_NETWORK_LETTER: &'static str = "N";
const ATTACK_VECTOR_ADJACENT_LETTER: &'static str = "A";
const ATTACK_VECTOR_LOCAL_LETTER: &'static str = "L";
const ATTACK_VECTOR_PHYSICAL_LETTER: &'static str = "P";

const ATTACK_COMPLEXITY_NOTDEFINED_WEIGHT: f32 = 1.0;
const ATTACK_COMPLEXITY_LOW_WEIGHT: f32 = 0.77;
const ATTACK_COMPLEXITY_HIGH_WEIGHT: f32 = 0.44;
const ATTACK_COMPLEXITY_NOTDEFINED_LETTER: &'static str = "X";
const ATTACK_COMPLEXITY_LOW_LETTER: &'static str = "L";
const ATTACK_COMPLEXITY_HIGH_LETTER: &'static str = "H";

const PRIVILEGES_REQUIRED_NOTDEFINED_WEIGHT: f32 = 1.0;
const PRIVILEGES_REQUIRED_NONE_WEIGHT: f32 = 0.85;
const PRIVILEGES_REQUIRED_LOW_SCOPE_CHANGED_WEIGHT: f32 = 0.68;
const PRIVILEGES_REQUIRED_LOW_SCOPE_UNCHANGED_WEIGHT: f32 = 0.62;
const PRIVILEGES_REQUIRED_HIGH_SCOPE_CHANGED_WEIGHT: f32 = 0.50;
const PRIVILEGES_REQUIRED_HIGH_SCOPE_UNCHANGED_WEIGHT: f32 = 0.27;
const PRIVILEGES_REQUIRED_NOTDEFINED_LETTER: &'static str = "X";
const PRIVILEGES_REQUIRED_NONE_LETTER: &'static str = "N";
const PRIVILEGES_REQUIRED_LOW_LETTER: &'static str = "L";
const PRIVILEGES_REQUIRED_HIGH_LETTER: &'static str = "H";

const USER_INTERACTION_NOTDEFINED_WEIGHT: f32 = 1.0;
const USER_INTERACTION_NONE_WEIGHT: f32 = 0.85;
const USER_INTERACTION_REQUIRED_WEIGHT: f32 = 0.62;
const USER_INTERACTION_NOTDEFINED_LETTER: &'static str = "X";
const USER_INTERACTION_NONE_LETTER: &'static str = "N";
const USER_INTERACTION_REQUIRED_LETTER: &'static str = "R";

const SCOPE_NOTDEFINED_LETTER: &'static str = "X";
const SCOPE_UNCHANGED_LETTER: &'static str = "U";
const SCOPE_CHANGED_LETTER: &'static str = "C";

const IMPACT_NOTDEFINED_WEIGHT: f32 = 1.0;
const IMPACT_HIGH_WEIGHT: f32 = 0.56;
const IMPACT_LOW_WEIGHT: f32 = 0.22;
const IMPACT_NONE_WEIGHT: f32 = 0.0;
const IMPACT_NOTDEFINED_LETTER: &'static str = "X";
const IMPACT_HIGH_LETTER: &'static str = "H";
const IMPACT_LOW_LETTER: &'static str = "L";
const IMPACT_NONE_LETTER: &'static str = "N";

const EXPLOIT_CODE_MATURITY_NOTDEFINED_WEIGHT: f32 = 1.0;
const EXPLOIT_CODE_MATURITY_HIGH_WEIGHT: f32 = 1.0;
const EXPLOIT_CODE_MATURITY_FUNCTIONAL_WEIGHT: f32 = 0.97;
const EXPLOIT_CODE_MATURITY_PROOFOFCONCEPT_WEIGHT: f32 = 0.94;
const EXPLOIT_CODE_MATURITY_UNPROVEN_WEIGHT: f32 = 0.91;
const EXPLOIT_CODE_MATURITY_NOTDEFINED_LETTER: &'static str = "X";
const EXPLOIT_CODE_MATURITY_HIGH_LETTER: &'static str = "H";
const EXPLOIT_CODE_MATURITY_FUNCTIONAL_LETTER: &'static str = "F";
const EXPLOIT_CODE_MATURITY_PROOFOFCONCEPT_LETTER: &'static str = "P";
const EXPLOIT_CODE_MATURITY_UNPROVEN_LETTER: &'static str = "U";

const REMEDIATION_LEVEL_NOTDEFINED_WEIGHT: f32 = 1.0;
const REMEDIATION_LEVEL_UNAVAILABLE_WEIGHT: f32 = 1.0;
const REMEDIATION_LEVEL_WORKAROUND_WEIGHT: f32 = 0.97;
const REMEDIATION_LEVEL_TEMPORARY_WEIGHT: f32 = 0.96;
const REMEDIATION_LEVEL_OFFICIALFIX_WEIGHT: f32 = 0.95;
const REMEDIATION_LEVEL_NOTDEFINED_LETTER: &'static str = "X";
const REMEDIATION_LEVEL_UNAVAILABLE_LETTER: &'static str = "U";
const REMEDIATION_LEVEL_WORKAROUND_LETTER: &'static str = "W";
const REMEDIATION_LEVEL_TEMPORARY_LETTER: &'static str = "T";
const REMEDIATION_LEVEL_OFFICIALFIX_LETTER: &'static str = "O";

const REPORT_CONFIDENCE_NOTDEFINED_WEIGHT: f32 = 1.0;
const REPORT_CONFIDENCE_CONFIRMED_WEIGHT: f32 = 1.0;
const REPORT_CONFIDENCE_REASONABLE_WEIGHT: f32 = 0.96;
const REPORT_CONFIDENCE_UNKNOWN_WEIGHT: f32 = 0.92;
const REPORT_CONFIDENCE_NOTDEFINED_LETTER: &'static str = "X";
const REPORT_CONFIDENCE_CONFIRMED_LETTER: &'static str = "C";
const REPORT_CONFIDENCE_REASONABLE_LETTER: &'static str = "R";
const REPORT_CONFIDENCE_UNKNOWN_LETTER: &'static str = "U";

const SECURITY_REQUIREMENT_NOTDEFINED_WEIGHT: f32 = 1.0;
const SECURITY_REQUIREMENT_HIGH_WEIGHT: f32 = 1.5;
const SECURITY_REQUIREMENT_MEDIUM_WEIGHT: f32 = 1.0;
const SECURITY_REQUIREMENT_LOW_WEIGHT: f32 = 0.5;
const SECURITY_REQUIREMENT_NOTDEFINED_LETTER: &'static str = "X";
const SECURITY_REQUIREMENT_HIGH_LETTER: &'static str = "H";
const SECURITY_REQUIREMENT_MEDIUM_LETTER: &'static str = "M";
const SECURITY_REQUIREMENT_LOW_LETTER: &'static str = "L";


#[derive(PartialEq,PartialOrd)]
pub enum AttackVector {
    NotDefined,
    Network,
    Adjacent,
    Local,
    Physical
}

impl AttackVector {
    pub fn get_weight(&self) -> f32 {
        use self::AttackVector::*;
        match &self {
            NotDefined => ATTACK_VECTOR_NOTDEFINED_WEIGHT,
            Network    => ATTACK_VECTOR_NETWORK_WEIGHT,
            Adjacent   => ATTACK_VECTOR_ADJACENT_WEIGHT,
            Local      => ATTACK_VECTOR_LOCAL_WEIGHT,
            Physical   => ATTACK_VECTOR_PHYSICAL_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::AttackVector::*;
        match &self {
            NotDefined => ATTACK_VECTOR_NOTDEFINED_LETTER,
            Network    => ATTACK_VECTOR_NETWORK_LETTER,
            Adjacent   => ATTACK_VECTOR_ADJACENT_LETTER,
            Local      => ATTACK_VECTOR_LOCAL_LETTER,
            Physical   => ATTACK_VECTOR_PHYSICAL_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> AttackVector {
        match metric_name.as_str() {
            ATTACK_VECTOR_NOTDEFINED_LETTER => AttackVector::NotDefined,
            ATTACK_VECTOR_NETWORK_LETTER => AttackVector::Network,
            ATTACK_VECTOR_ADJACENT_LETTER => AttackVector::Adjacent,
            ATTACK_VECTOR_LOCAL_LETTER => AttackVector::Local,
            ATTACK_VECTOR_PHYSICAL_LETTER => AttackVector::Physical,
            &_ => AttackVector::NotDefined
        }
    }
}

#[test]
fn test_attack_vector_get_weight() {
    assert_eq!(AttackVector::NotDefined.get_weight(), ATTACK_VECTOR_NOTDEFINED_WEIGHT);
    assert_eq!(AttackVector::Network.get_weight(), ATTACK_VECTOR_NETWORK_WEIGHT);
    assert_eq!(AttackVector::Adjacent.get_weight(), ATTACK_VECTOR_ADJACENT_WEIGHT);
    assert_eq!(AttackVector::Local.get_weight(), ATTACK_VECTOR_LOCAL_WEIGHT);
    assert_eq!(AttackVector::Physical.get_weight(), ATTACK_VECTOR_PHYSICAL_WEIGHT);
}

#[test]
fn test_attack_vector_get_letter() {
    assert_eq!(AttackVector::NotDefined.get_letter(), ATTACK_VECTOR_NOTDEFINED_LETTER);
    assert_eq!(AttackVector::Network.get_letter(), ATTACK_VECTOR_NETWORK_LETTER);
    assert_eq!(AttackVector::Adjacent.get_letter(), ATTACK_VECTOR_ADJACENT_LETTER);
    assert_eq!(AttackVector::Local.get_letter(), ATTACK_VECTOR_LOCAL_LETTER);
    assert_eq!(AttackVector::Physical.get_letter(), ATTACK_VECTOR_PHYSICAL_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum AttackComplexity {
    NotDefined,
    Low,
    High
}

impl AttackComplexity {
    pub fn get_weight(&self) -> f32 {
        use self::AttackComplexity::*;
        match &self {
            NotDefined => ATTACK_COMPLEXITY_NOTDEFINED_WEIGHT,
            Low        => ATTACK_COMPLEXITY_LOW_WEIGHT,
            High       => ATTACK_COMPLEXITY_HIGH_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::AttackComplexity::*;
        match &self {
            NotDefined => ATTACK_COMPLEXITY_NOTDEFINED_LETTER,
            Low        => ATTACK_COMPLEXITY_LOW_LETTER,
            High       => ATTACK_COMPLEXITY_HIGH_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> AttackComplexity {
        match metric_name.as_ref() {
            ATTACK_COMPLEXITY_NOTDEFINED_LETTER => AttackComplexity::NotDefined,
            ATTACK_COMPLEXITY_LOW_LETTER => AttackComplexity::Low,
            ATTACK_COMPLEXITY_HIGH_LETTER => AttackComplexity::High,
            &_ => AttackComplexity::NotDefined
        }
    }
}

#[test]
fn test_attack_complexity_get_weight() {
    assert_eq!(AttackComplexity::NotDefined.get_weight(), ATTACK_COMPLEXITY_NOTDEFINED_WEIGHT);
    assert_eq!(AttackComplexity::Low.get_weight(), ATTACK_COMPLEXITY_LOW_WEIGHT);
    assert_eq!(AttackComplexity::High.get_weight(), ATTACK_COMPLEXITY_HIGH_WEIGHT);
}

#[test]
fn test_attack_complexity_get_letter() {
    assert_eq!(AttackComplexity::NotDefined.get_letter(), ATTACK_COMPLEXITY_NOTDEFINED_LETTER);
    assert_eq!(AttackComplexity::Low.get_letter(), ATTACK_COMPLEXITY_LOW_LETTER);
    assert_eq!(AttackComplexity::High.get_letter(), ATTACK_COMPLEXITY_HIGH_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum PrivilegesRequired {
    NotDefined,
    None,
    Low,
    High
}

impl PrivilegesRequired {
    pub fn get_weight(&self, s: Scope) -> f32 {
        use self::PrivilegesRequired::*;
        match &self {
            NotDefined                => PRIVILEGES_REQUIRED_NOTDEFINED_WEIGHT,
            PrivilegesRequired::None  => PRIVILEGES_REQUIRED_NONE_WEIGHT,
            Low                       => match s {
                Scope::Changed   => PRIVILEGES_REQUIRED_LOW_SCOPE_CHANGED_WEIGHT,
                Scope::Unchanged => PRIVILEGES_REQUIRED_LOW_SCOPE_UNCHANGED_WEIGHT,
                _ => PRIVILEGES_REQUIRED_NOTDEFINED_WEIGHT
            },
            High                      => match s {
                Scope::Changed   => PRIVILEGES_REQUIRED_HIGH_SCOPE_CHANGED_WEIGHT,
                Scope::Unchanged => PRIVILEGES_REQUIRED_HIGH_SCOPE_UNCHANGED_WEIGHT,
                _ => PRIVILEGES_REQUIRED_NOTDEFINED_WEIGHT
            }
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::PrivilegesRequired::*;
        match &self {
            NotDefined                => PRIVILEGES_REQUIRED_NOTDEFINED_LETTER,
            PrivilegesRequired::None  => PRIVILEGES_REQUIRED_NONE_LETTER,
            Low                       => PRIVILEGES_REQUIRED_LOW_LETTER,
            High                      => PRIVILEGES_REQUIRED_HIGH_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> PrivilegesRequired {
        match metric_name.as_ref(){
            PRIVILEGES_REQUIRED_NOTDEFINED_LETTER => PrivilegesRequired::NotDefined,
            PRIVILEGES_REQUIRED_NONE_LETTER => PrivilegesRequired::None,
            PRIVILEGES_REQUIRED_LOW_LETTER => PrivilegesRequired::Low,
            PRIVILEGES_REQUIRED_HIGH_LETTER => PrivilegesRequired::High,
            &_ => PrivilegesRequired::NotDefined
        }
    }
}

#[test]
fn test_privileges_required_get_weight() {
    assert_eq!(PrivilegesRequired::NotDefined.get_weight(Scope::Unchanged), PRIVILEGES_REQUIRED_NOTDEFINED_WEIGHT);
    assert_eq!(PrivilegesRequired::None.get_weight(Scope::Unchanged), PRIVILEGES_REQUIRED_NONE_WEIGHT);
    assert_eq!(PrivilegesRequired::Low.get_weight(Scope::Changed), PRIVILEGES_REQUIRED_LOW_SCOPE_CHANGED_WEIGHT);
    assert_eq!(PrivilegesRequired::Low.get_weight(Scope::Unchanged), PRIVILEGES_REQUIRED_LOW_SCOPE_UNCHANGED_WEIGHT);
    assert_eq!(PrivilegesRequired::High.get_weight(Scope::Changed), PRIVILEGES_REQUIRED_HIGH_SCOPE_CHANGED_WEIGHT);
    assert_eq!(PrivilegesRequired::High.get_weight(Scope::Unchanged), PRIVILEGES_REQUIRED_HIGH_SCOPE_UNCHANGED_WEIGHT);
}

#[test]
fn test_privileges_required_get_letter() {
    assert_eq!(PrivilegesRequired::NotDefined.get_letter(), PRIVILEGES_REQUIRED_NOTDEFINED_LETTER);
    assert_eq!(PrivilegesRequired::None.get_letter(), PRIVILEGES_REQUIRED_NONE_LETTER);
    assert_eq!(PrivilegesRequired::Low.get_letter(), PRIVILEGES_REQUIRED_LOW_LETTER);
    assert_eq!(PrivilegesRequired::High.get_letter(), PRIVILEGES_REQUIRED_HIGH_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum UserInteraction {
    NotDefined,
    None,
    Required
}

impl UserInteraction {
    pub fn get_weight(&self) -> f32 {
        use self::UserInteraction::*;
        match &self {
            NotDefined                => USER_INTERACTION_NOTDEFINED_WEIGHT,
            UserInteraction::None     => USER_INTERACTION_NONE_WEIGHT,
            Required                  => USER_INTERACTION_REQUIRED_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::UserInteraction::*;
        match &self {
            NotDefined                => USER_INTERACTION_NOTDEFINED_LETTER,
            UserInteraction::None     => USER_INTERACTION_NONE_LETTER,
            Required                  => USER_INTERACTION_REQUIRED_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> UserInteraction {
        match metric_name.as_ref(){
            USER_INTERACTION_NOTDEFINED_LETTER => UserInteraction::NotDefined,
            USER_INTERACTION_NONE_LETTER => UserInteraction::None,
            USER_INTERACTION_REQUIRED_LETTER => UserInteraction::Required,
            &_ => UserInteraction::NotDefined
        }
    }
}

#[test]
fn test_user_interaction_get_weight() {
    assert_eq!(UserInteraction::NotDefined.get_weight(), USER_INTERACTION_NOTDEFINED_WEIGHT);
    assert_eq!(UserInteraction::None.get_weight(), USER_INTERACTION_NONE_WEIGHT);
    assert_eq!(UserInteraction::Required.get_weight(), USER_INTERACTION_REQUIRED_WEIGHT);
}

#[test]
fn test_user_interaction_get_letter() {
    assert_eq!(UserInteraction::NotDefined.get_letter(), USER_INTERACTION_NOTDEFINED_LETTER);
    assert_eq!(UserInteraction::None.get_letter(), USER_INTERACTION_NONE_LETTER);
    assert_eq!(UserInteraction::Required.get_letter(), USER_INTERACTION_REQUIRED_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum Scope {
    NotDefined,
    Unchanged,
    Changed
}

impl Scope {
    pub fn get_letter(&self) -> &'static str {
        use self::Scope::*;
        match &self {
            NotDefined => SCOPE_NOTDEFINED_LETTER,
            Unchanged  => SCOPE_UNCHANGED_LETTER,
            Changed    => SCOPE_CHANGED_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> Scope {
        match metric_name.as_ref(){
            SCOPE_NOTDEFINED_LETTER => Scope::NotDefined,
            SCOPE_UNCHANGED_LETTER => Scope::Unchanged,
            SCOPE_CHANGED_LETTER => Scope::Changed,
            &_ => Scope::NotDefined
        }
    }
}

#[test]
fn test_scope_get_letter() {
    assert_eq!(Scope::NotDefined.get_letter(), SCOPE_NOTDEFINED_LETTER);
    assert_eq!(Scope::Unchanged.get_letter(), SCOPE_UNCHANGED_LETTER);
    assert_eq!(Scope::Changed.get_letter(), SCOPE_CHANGED_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum Impact {
    NotDefined,
    High,
    Low,
    None
}

impl Impact {
    pub fn get_weight(&self) -> f32 {
        use self::Impact::*;
        match &self {
            NotDefined   => IMPACT_NOTDEFINED_WEIGHT,
            High         => IMPACT_HIGH_WEIGHT,
            Low          => IMPACT_LOW_WEIGHT,
            Impact::None => IMPACT_NONE_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::Impact::*;
        match &self {
            NotDefined   => IMPACT_NOTDEFINED_LETTER,
            High         => IMPACT_HIGH_LETTER,
            Low          => IMPACT_LOW_LETTER,
            Impact::None => IMPACT_NONE_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> Impact {
        match metric_name.as_ref(){
            IMPACT_NOTDEFINED_LETTER => Impact::NotDefined,
            IMPACT_HIGH_LETTER => Impact::High,
            IMPACT_LOW_LETTER => Impact::Low,
            IMPACT_NONE_LETTER => Impact::None,
            &_ => Impact::NotDefined
        }
    }
}

#[test]
fn test_impact_get_weight() {
    assert_eq!(Impact::NotDefined.get_weight(), IMPACT_NOTDEFINED_WEIGHT);
    assert_eq!(Impact::High.get_weight(), IMPACT_HIGH_WEIGHT);
    assert_eq!(Impact::Low.get_weight(), IMPACT_LOW_WEIGHT);
    assert_eq!(Impact::None.get_weight(), IMPACT_NONE_WEIGHT);
}

#[test]
fn test_impact_get_letter() {
    assert_eq!(Impact::NotDefined.get_letter(), IMPACT_NOTDEFINED_LETTER);
    assert_eq!(Impact::High.get_letter(), IMPACT_HIGH_LETTER);
    assert_eq!(Impact::Low.get_letter(), IMPACT_LOW_LETTER);
    assert_eq!(Impact::None.get_letter(), IMPACT_NONE_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum ExploitCodeMaturity {
    NotDefined,
    High,
    Functional,
    ProofOfConcept,
    Unproven
}

impl ExploitCodeMaturity {
    pub fn get_weight(&self) -> f32 {
        use self::ExploitCodeMaturity::*;
        match &self {
            NotDefined     => EXPLOIT_CODE_MATURITY_NOTDEFINED_WEIGHT,
            High           => EXPLOIT_CODE_MATURITY_HIGH_WEIGHT,
            Functional     => EXPLOIT_CODE_MATURITY_FUNCTIONAL_WEIGHT,
            ProofOfConcept => EXPLOIT_CODE_MATURITY_PROOFOFCONCEPT_WEIGHT,
            Unproven       => EXPLOIT_CODE_MATURITY_UNPROVEN_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::ExploitCodeMaturity::*;
        match &self {
            NotDefined     => EXPLOIT_CODE_MATURITY_NOTDEFINED_LETTER,
            High           => EXPLOIT_CODE_MATURITY_HIGH_LETTER,
            Functional     => EXPLOIT_CODE_MATURITY_FUNCTIONAL_LETTER,
            ProofOfConcept => EXPLOIT_CODE_MATURITY_PROOFOFCONCEPT_LETTER,
            Unproven       => EXPLOIT_CODE_MATURITY_UNPROVEN_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> ExploitCodeMaturity {
        match metric_name.as_ref(){
            EXPLOIT_CODE_MATURITY_NOTDEFINED_LETTER => ExploitCodeMaturity::NotDefined,
            EXPLOIT_CODE_MATURITY_HIGH_LETTER => ExploitCodeMaturity::High,
            EXPLOIT_CODE_MATURITY_FUNCTIONAL_LETTER => ExploitCodeMaturity::Functional,
            EXPLOIT_CODE_MATURITY_PROOFOFCONCEPT_LETTER => ExploitCodeMaturity::ProofOfConcept,
            EXPLOIT_CODE_MATURITY_UNPROVEN_LETTER => ExploitCodeMaturity::Unproven,
            &_ => ExploitCodeMaturity::NotDefined
        }
    }
}

#[test]
fn test_exploit_code_maturity_get_weight() {
    assert_eq!(ExploitCodeMaturity::NotDefined.get_weight(), EXPLOIT_CODE_MATURITY_NOTDEFINED_WEIGHT);
    assert_eq!(ExploitCodeMaturity::High.get_weight(), EXPLOIT_CODE_MATURITY_HIGH_WEIGHT);
    assert_eq!(ExploitCodeMaturity::Functional.get_weight(), EXPLOIT_CODE_MATURITY_FUNCTIONAL_WEIGHT);
    assert_eq!(ExploitCodeMaturity::ProofOfConcept.get_weight(), EXPLOIT_CODE_MATURITY_PROOFOFCONCEPT_WEIGHT);
    assert_eq!(ExploitCodeMaturity::Unproven.get_weight(), EXPLOIT_CODE_MATURITY_UNPROVEN_WEIGHT);
}

#[test]
fn test_exploit_code_maturity_get_letter() {
    assert_eq!(ExploitCodeMaturity::NotDefined.get_letter(), EXPLOIT_CODE_MATURITY_NOTDEFINED_LETTER);
    assert_eq!(ExploitCodeMaturity::High.get_letter(), EXPLOIT_CODE_MATURITY_HIGH_LETTER);
    assert_eq!(ExploitCodeMaturity::Functional.get_letter(), EXPLOIT_CODE_MATURITY_FUNCTIONAL_LETTER);
    assert_eq!(ExploitCodeMaturity::ProofOfConcept.get_letter(), EXPLOIT_CODE_MATURITY_PROOFOFCONCEPT_LETTER);
    assert_eq!(ExploitCodeMaturity::Unproven.get_letter(), EXPLOIT_CODE_MATURITY_UNPROVEN_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum RemediationLevel {
    NotDefined,
    Unavailable,
    Workaround,
    Temporary,
    OfficialFix
}

impl RemediationLevel {
    pub fn get_weight(&self) -> f32 {
        use self::RemediationLevel::*;
        match &self {
            NotDefined  => REMEDIATION_LEVEL_NOTDEFINED_WEIGHT,
            Unavailable => REMEDIATION_LEVEL_UNAVAILABLE_WEIGHT,
            Workaround  => REMEDIATION_LEVEL_WORKAROUND_WEIGHT,
            Temporary   => REMEDIATION_LEVEL_TEMPORARY_WEIGHT,
            OfficialFix => REMEDIATION_LEVEL_OFFICIALFIX_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::RemediationLevel::*;
        match &self {
            NotDefined  => REMEDIATION_LEVEL_NOTDEFINED_LETTER,
            Unavailable => REMEDIATION_LEVEL_UNAVAILABLE_LETTER,
            Workaround  => REMEDIATION_LEVEL_WORKAROUND_LETTER,
            Temporary   => REMEDIATION_LEVEL_TEMPORARY_LETTER,
            OfficialFix => REMEDIATION_LEVEL_OFFICIALFIX_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> RemediationLevel {
        match metric_name.as_ref(){
            REMEDIATION_LEVEL_NOTDEFINED_LETTER => RemediationLevel::NotDefined,
            REMEDIATION_LEVEL_UNAVAILABLE_LETTER => RemediationLevel::Unavailable,
            REMEDIATION_LEVEL_WORKAROUND_LETTER => RemediationLevel::Workaround,
            REMEDIATION_LEVEL_TEMPORARY_LETTER => RemediationLevel::Temporary,
            REMEDIATION_LEVEL_OFFICIALFIX_LETTER => RemediationLevel::OfficialFix,
            &_ => RemediationLevel::NotDefined
        }
    }
}

#[test]
fn test_remediation_level_get_weight() {
    assert_eq!(RemediationLevel::NotDefined.get_weight(), REMEDIATION_LEVEL_NOTDEFINED_WEIGHT);
    assert_eq!(RemediationLevel::Unavailable.get_weight(), REMEDIATION_LEVEL_UNAVAILABLE_WEIGHT);
    assert_eq!(RemediationLevel::Workaround.get_weight(), REMEDIATION_LEVEL_WORKAROUND_WEIGHT);
    assert_eq!(RemediationLevel::Temporary.get_weight(), REMEDIATION_LEVEL_TEMPORARY_WEIGHT);
    assert_eq!(RemediationLevel::OfficialFix.get_weight(), REMEDIATION_LEVEL_OFFICIALFIX_WEIGHT);
}

#[test]
fn test_remediation_level_get_letter() {
    assert_eq!(RemediationLevel::NotDefined.get_letter(), REMEDIATION_LEVEL_NOTDEFINED_LETTER);
    assert_eq!(RemediationLevel::Unavailable.get_letter(), REMEDIATION_LEVEL_UNAVAILABLE_LETTER);
    assert_eq!(RemediationLevel::Workaround.get_letter(), REMEDIATION_LEVEL_WORKAROUND_LETTER);
    assert_eq!(RemediationLevel::Temporary.get_letter(), REMEDIATION_LEVEL_TEMPORARY_LETTER);
    assert_eq!(RemediationLevel::OfficialFix.get_letter(), REMEDIATION_LEVEL_OFFICIALFIX_LETTER);
}

#[derive(PartialEq,PartialOrd)]
pub enum ReportConfidence {
    NotDefined,
    Confirmed,
    Reasonable,
    Unknown
}

impl ReportConfidence {
    pub fn get_weight(&self) -> f32 {
        use self::ReportConfidence::*;
        match &self {
            NotDefined => REPORT_CONFIDENCE_NOTDEFINED_WEIGHT,
            Confirmed  => REPORT_CONFIDENCE_CONFIRMED_WEIGHT,
            Reasonable => REPORT_CONFIDENCE_REASONABLE_WEIGHT,
            Unknown    => REPORT_CONFIDENCE_UNKNOWN_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::ReportConfidence::*;
        match &self {
            NotDefined => REPORT_CONFIDENCE_NOTDEFINED_LETTER,
            Confirmed  => REPORT_CONFIDENCE_CONFIRMED_LETTER,
            Reasonable => REPORT_CONFIDENCE_REASONABLE_LETTER,
            Unknown    => REPORT_CONFIDENCE_UNKNOWN_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> ReportConfidence {
        match metric_name.as_ref(){
            REPORT_CONFIDENCE_NOTDEFINED_LETTER => ReportConfidence::NotDefined,
            REPORT_CONFIDENCE_CONFIRMED_LETTER => ReportConfidence::Confirmed,
            REPORT_CONFIDENCE_REASONABLE_LETTER => ReportConfidence::Reasonable,
            REPORT_CONFIDENCE_UNKNOWN_LETTER => ReportConfidence::Unknown,
            &_ => ReportConfidence::NotDefined
        }
    }
}

#[test]
fn test_report_confidence_get_weight() {
    assert_eq!(ReportConfidence::NotDefined.get_weight(), REPORT_CONFIDENCE_NOTDEFINED_WEIGHT);
    assert_eq!(ReportConfidence::Confirmed.get_weight(), REPORT_CONFIDENCE_CONFIRMED_WEIGHT);
    assert_eq!(ReportConfidence::Reasonable.get_weight(), REPORT_CONFIDENCE_REASONABLE_WEIGHT);
    assert_eq!(ReportConfidence::Unknown.get_weight(), REPORT_CONFIDENCE_UNKNOWN_WEIGHT);
}

#[test]
fn test_report_confidence_get_letter() {
    assert_eq!(ReportConfidence::NotDefined.get_letter(), REPORT_CONFIDENCE_NOTDEFINED_LETTER);
    assert_eq!(ReportConfidence::Confirmed.get_letter(), REPORT_CONFIDENCE_CONFIRMED_LETTER);
    assert_eq!(ReportConfidence::Reasonable.get_letter(), REPORT_CONFIDENCE_REASONABLE_LETTER);
    assert_eq!(ReportConfidence::Unknown.get_letter(), REPORT_CONFIDENCE_UNKNOWN_LETTER);
}

#[derive(Debug,PartialEq,PartialOrd,)]
pub enum QualitativeSeverityRating {
    None,
    Low,
    Medium,
    High,
    Critical
}

trait InRange {
    fn in_range(&self, begin: Self, end: Self) -> bool;
}

impl InRange for f32 {
    fn in_range(&self, begin: f32, end: f32) -> bool {
        *self >= begin && * self <= end
    }
}

impl QualitativeSeverityRating {
    pub fn from_quantitative_rating(quantitative_rating: f32) -> QualitativeSeverityRating {
        match quantitative_rating {
            x if x == 0.0              => QualitativeSeverityRating::None,
            x if x.in_range(0.1, 3.9)  => QualitativeSeverityRating::Low,
            x if x.in_range(4.0, 6.9)  => QualitativeSeverityRating::Medium,
            x if x.in_range(7.0, 8.9)  => QualitativeSeverityRating::High,
            x if x.in_range(9.0, 10.0) => QualitativeSeverityRating::Critical,
            _                          => QualitativeSeverityRating::None
        }
    }
}

#[test]
fn test_qualitative_severity_rating() {
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(0.0), QualitativeSeverityRating::None);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(0.1), QualitativeSeverityRating::Low);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(0.2), QualitativeSeverityRating::Low);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(3.8), QualitativeSeverityRating::Low);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(3.9), QualitativeSeverityRating::Low);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(4.0), QualitativeSeverityRating::Medium);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(4.1), QualitativeSeverityRating::Medium);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(6.8), QualitativeSeverityRating::Medium);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(6.9), QualitativeSeverityRating::Medium);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(7.0), QualitativeSeverityRating::High);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(7.1), QualitativeSeverityRating::High);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(8.8), QualitativeSeverityRating::High);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(8.9), QualitativeSeverityRating::High);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(9.0), QualitativeSeverityRating::Critical);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(9.1), QualitativeSeverityRating::Critical);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(9.9), QualitativeSeverityRating::Critical);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(10.0), QualitativeSeverityRating::Critical);
    assert_eq!(QualitativeSeverityRating::from_quantitative_rating(10.1), QualitativeSeverityRating::None);
}

#[derive(PartialEq,PartialOrd)]
pub enum SecurityRequirement {
    NotDefined,
    High,
    Medium,
    Low
}

impl SecurityRequirement {
    pub fn get_weight(&self) -> f32 {
        use self::SecurityRequirement::*;
        match &self {
            NotDefined => SECURITY_REQUIREMENT_NOTDEFINED_WEIGHT,
            High       => SECURITY_REQUIREMENT_HIGH_WEIGHT,
            Medium     => SECURITY_REQUIREMENT_MEDIUM_WEIGHT,
            Low        => SECURITY_REQUIREMENT_LOW_WEIGHT
        }
    }

    pub fn get_letter(&self) -> &'static str {
        use self::SecurityRequirement::*;
        match &self {
            NotDefined => SECURITY_REQUIREMENT_NOTDEFINED_LETTER,
            High       => SECURITY_REQUIREMENT_HIGH_LETTER,
            Medium     => SECURITY_REQUIREMENT_MEDIUM_LETTER,
            Low        => SECURITY_REQUIREMENT_LOW_LETTER
        }
    }

    pub fn match_metric_value(metric_name: &String) -> SecurityRequirement {
        match metric_name.as_ref(){
            SECURITY_REQUIREMENT_NOTDEFINED_LETTER => SecurityRequirement::NotDefined,
            SECURITY_REQUIREMENT_HIGH_LETTER => SecurityRequirement::High,
            SECURITY_REQUIREMENT_MEDIUM_LETTER => SecurityRequirement::Medium,
            SECURITY_REQUIREMENT_LOW_LETTER => SecurityRequirement::Low,
            &_ => SecurityRequirement::NotDefined
        }
    }
}

#[test]
fn test_security_requirement_get_weight() {
    assert_eq!(SecurityRequirement::NotDefined.get_weight(), SECURITY_REQUIREMENT_NOTDEFINED_WEIGHT);
    assert_eq!(SecurityRequirement::High.get_weight(), SECURITY_REQUIREMENT_HIGH_WEIGHT);
    assert_eq!(SecurityRequirement::Medium.get_weight(), SECURITY_REQUIREMENT_MEDIUM_WEIGHT);
    assert_eq!(SecurityRequirement::Low.get_weight(), SECURITY_REQUIREMENT_LOW_WEIGHT);
}

#[test]
fn test_security_requirement_get_letter() {
    assert_eq!(SecurityRequirement::NotDefined.get_letter(), SECURITY_REQUIREMENT_NOTDEFINED_LETTER);
    assert_eq!(SecurityRequirement::High.get_letter(), SECURITY_REQUIREMENT_HIGH_LETTER);
    assert_eq!(SecurityRequirement::Medium.get_letter(), SECURITY_REQUIREMENT_MEDIUM_LETTER);
    assert_eq!(SecurityRequirement::Low.get_letter(), SECURITY_REQUIREMENT_LOW_LETTER);
}
