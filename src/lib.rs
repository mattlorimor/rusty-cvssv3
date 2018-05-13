mod enums;

pub struct CVSSv3 {
    // Base
    pub attack_vector:                       enums::AttackVector,
    pub attack_complexity:                   enums::AttackComplexity,
    pub privileges_required:                 enums::PrivilegesRequired,
    pub user_interaction:                    enums::UserInteraction,
    pub scope:                               enums::Scope,
    pub confidentiality_impact:              enums::Impact,
    pub integrity_impact:                    enums::Impact,
    pub availability_impact:                 enums::Impact,

    // Temporal
    pub exploit_code_maturity:               enums::ExploitCodeMaturity,
    pub remediation_level:                   enums::RemediationLevel,
    pub report_confidence:                   enums::ReportConfidence,

    // Environmental
    pub confidentiality_requirement:         enums::SecurityRequirement,
    pub integrity_requirement:               enums::SecurityRequirement,
    pub availability_requirement:            enums::SecurityRequirement,
    pub modified_attack_vector:              enums::AttackVector,
    pub modified_attack_complexity:          enums::AttackComplexity,
    pub modified_privileges_required:        enums::PrivilegesRequired,
    pub modified_user_interaction:           enums::UserInteraction,
    pub modified_scope:                      enums::Scope,
    pub modified_confidentiality_impact:     enums::Impact,
    pub modified_integrity_impact:           enums::Impact,
    pub modified_availability_impact:        enums::Impact
}

impl Default for CVSSv3 {
    fn default() -> CVSSv3 {
        CVSSv3 {
            // Base
            attack_vector:                       enums::AttackVector::NotDefined,
            attack_complexity:                   enums::AttackComplexity::NotDefined,
            privileges_required:                 enums::PrivilegesRequired::NotDefined,
            user_interaction:                    enums::UserInteraction::NotDefined,
            scope:                               enums::Scope::NotDefined,
            confidentiality_impact:              enums::Impact::NotDefined,
            integrity_impact:                    enums::Impact::NotDefined,
            availability_impact:                 enums::Impact::NotDefined,

            // Temporal
            exploit_code_maturity:               enums::ExploitCodeMaturity::NotDefined,
            remediation_level:                   enums::RemediationLevel::NotDefined,
            report_confidence:                   enums::ReportConfidence::NotDefined,

            //Environmental
            confidentiality_requirement:         enums::SecurityRequirement::NotDefined,
            integrity_requirement:               enums::SecurityRequirement::NotDefined,
            availability_requirement:            enums::SecurityRequirement::NotDefined,
            modified_attack_vector:              enums::AttackVector::NotDefined,
            modified_attack_complexity:          enums::AttackComplexity::NotDefined,
            modified_privileges_required:        enums::PrivilegesRequired::NotDefined,
            modified_user_interaction:           enums::UserInteraction::NotDefined,
            modified_scope:                      enums::Scope::NotDefined,
            modified_confidentiality_impact:     enums::Impact::NotDefined,
            modified_integrity_impact:           enums::Impact::NotDefined,
            modified_availability_impact:        enums::Impact::NotDefined
        }
    }
}

impl CVSSv3 {
    pub fn to_vector_string(&self, include_blanks: bool) -> String {
        let mut vector_string = String::new();
        vector_string.push_str("CVSS:3.0");
        if self.attack_vector.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/AV:X");
            }
        }
        else {
            vector_string.push_str(&format!("/AV:{}", self.attack_vector.get_letter()));
        }
        if self.attack_complexity.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/AC:X");
            }
        }
        else {
            vector_string.push_str(&format!("/AC:{}", self.attack_complexity.get_letter()));
        }
        if self.privileges_required.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/PR:X");
            }
        }
        else {
            vector_string.push_str(&format!("/PR:{}", self.privileges_required.get_letter()));
        }
        if self.user_interaction.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/UI:X");
            }
        }
        else {
            vector_string.push_str(&format!("/UI:{}", self.user_interaction.get_letter()));
        }
        if self.scope.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/S:X");
            }
        }
        else {
            vector_string.push_str(&format!("/S:{}", self.scope.get_letter()));
        }
        if self.confidentiality_impact.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/C:X");
            }
        }
        else {
            vector_string.push_str(&format!("/C:{}", self.confidentiality_impact.get_letter()));
        }
        if self.integrity_impact.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/I:X");
            }
        }
        else {
            vector_string.push_str(&format!("/I:{}", self.integrity_impact.get_letter()));
        }
        if self.availability_impact.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/A:X");
            }
        }
        else {
            vector_string.push_str(&format!("/A:{}", self.availability_impact.get_letter()));
        }
        if self.exploit_code_maturity.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/E:X");
            }
        }
        else {
            vector_string.push_str(&format!("/E:{}", self.exploit_code_maturity.get_letter()));
        }
        if self.remediation_level.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/RL:X");
            }
        }
        else {
            vector_string.push_str(&format!("/RL:{}", self.remediation_level.get_letter()));
        }
        if self.report_confidence.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/RC:X");
            }
        }
        else {
            vector_string.push_str(&format!("/RC:{}", self.report_confidence.get_letter()));
        }
        if self.confidentiality_requirement.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/CR:X");
            }
        }
        else {
            vector_string.push_str(&format!("/CR:{}", self.confidentiality_requirement.get_letter()));
        }
        if self.integrity_requirement.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/IR:X");
            }
        }
        else {
            vector_string.push_str(&format!("/IR:{}", self.integrity_requirement.get_letter()));
        }
        if self.availability_requirement.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/AR:X");
            }
        }
        else {
            vector_string.push_str(&format!("/AR:{}", self.availability_requirement.get_letter()));
        }
        if self.modified_attack_vector.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MAV:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MAV:{}", self.modified_attack_vector.get_letter()));
        }
        if self.modified_attack_complexity.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MAC:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MAC:{}", self.modified_attack_complexity.get_letter()));
        }
        if self.modified_privileges_required.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MPR:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MPR:{}", self.modified_privileges_required.get_letter()));
        }
        if self.modified_user_interaction.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MUI:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MUI:{}", self.modified_user_interaction.get_letter()));
        }
        if self.modified_scope.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MS:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MS:{}", self.modified_scope.get_letter()));
        }
        if self.modified_confidentiality_impact.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MC:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MC:{}", self.modified_confidentiality_impact.get_letter()));
        }
        if self.modified_integrity_impact.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MI:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MI:{}", self.modified_integrity_impact.get_letter()));
        }
        if self.modified_availability_impact.get_letter() == "X" {
            if include_blanks == true {
                vector_string.push_str("/MA:X");
            }
        }
        else {
            vector_string.push_str(&format!("/MA:{}", self.modified_availability_impact.get_letter()));
        }
        vector_string
    }

    pub fn base_score(&self) -> f32 {
        let impact_sub_score_base    = self.impact_sub_score_base();
        let impact_sub_score         = self.impact_sub_score(&self.scope, impact_sub_score_base);
        let exploitability_sub_score = self.exploitability_sub_score();

        if impact_sub_score <= 0.0 {
            return 0.0;
        }
        else {
            match self.scope {
                enums::Scope::Unchanged  => (impact_sub_score + exploitability_sub_score.min(10.0))
                                                                                        .round_up(1),
                enums::Scope::Changed    => ((1.08 * (impact_sub_score + exploitability_sub_score)).min(10.0))
                                                                                                   .round_up(1),
                enums::Scope::NotDefined => panic!("Scope is not defined")
            }
        }
    }

    pub fn temporal_score(&self) -> f32 {
        let base_score                   = self.base_score();
        let exploit_code_maturity_weight = self.exploit_code_maturity.get_weight();
        let remediation_level_weight     = self.remediation_level.get_weight();
        let report_confidence_weight     = self.report_confidence.get_weight();

        (base_score * exploit_code_maturity_weight * remediation_level_weight
            * report_confidence_weight).round_up(1)
    }

    fn impact_sub_score_base(&self) -> f32 {
        let confidentiality_impact = self.confidentiality_impact.get_weight();
        let integrity_impact       = self.integrity_impact.get_weight();
        let availability_impact    = self.availability_impact.get_weight();

        1.0 - ((1.0 - confidentiality_impact) * (1.0 - integrity_impact) * (1.0 - availability_impact))
    }

    fn impact_sub_score(&self, scope: &enums::Scope, sub_score: f32) -> f32 {
        match scope {
            enums::Scope::Unchanged  => 6.42 * sub_score,
            enums::Scope::Changed    => 7.52 * (sub_score - 0.029) - 3.25
                                        * (sub_score - 0.02).powf(15.0),
            enums::Scope::NotDefined => panic!("Scope is not defined")
        }
    }

    fn exploitability_sub_score(&self) -> f32 {
        let _scope = {
            match self.scope {
                enums::Scope::Unchanged  => enums::Scope::Unchanged,
                enums::Scope::Changed    => enums::Scope::Changed,
                enums::Scope::NotDefined => panic!("Scope is not defined")
            }
        };

        let attack_vector_weight       = self.attack_vector.get_weight();
        let attack_complexity_weight   = self.attack_complexity.get_weight();
        let privileges_required_weight = self.privileges_required.get_weight(_scope);
        let user_interaction_weight    = self.user_interaction.get_weight();

        8.22 * attack_vector_weight * attack_complexity_weight * privileges_required_weight
        * user_interaction_weight
    }

    fn modified_impact_sub_score_base(&self) -> f32 {
        let confidentiality_requirement     = self.confidentiality_requirement.get_weight();
        let integrity_requirement           = self.integrity_requirement.get_weight();
        let availability_requirement        = self.availability_requirement.get_weight();

        // Determine whether the unmodified C/I/A weights should be used
        let modified_confidentiality_impact = match self.modified_confidentiality_impact {
            enums::Impact::NotDefined => self.confidentiality_impact.get_weight(),
            _ => self.modified_confidentiality_impact.get_weight()
        };
        let modified_integrity_impact       = match self.modified_integrity_impact {
            enums::Impact::NotDefined => self.integrity_impact.get_weight(),
            _ => self.modified_integrity_impact.get_weight()
        };
        let modified_availability_impact    = match self.modified_availability_impact {
            enums::Impact::NotDefined => self.availability_impact.get_weight(),
            _ => self.modified_availability_impact.get_weight()
        };

        ((1.0 - (1.0 - modified_confidentiality_impact * confidentiality_requirement)
        * (1.0 - modified_integrity_impact * integrity_requirement)
        * (1.0 - modified_availability_impact * availability_requirement))).min(0.915)
    }

    fn modified_impact_sub_score(&self) -> f32 {
        let _scope = match self.modified_scope {
            enums::Scope::NotDefined => &self.scope,
            _ => &self.modified_scope
        };
        let impact_sub_score_base = self.modified_impact_sub_score_base();

        self.impact_sub_score(_scope, impact_sub_score_base)
    }

    fn modified_exploitability_sub_score(&self) -> f32 {
        let modified_scope = match self.modified_scope {
            enums::Scope::NotDefined => &self.scope,
            _ => &self.modified_scope
        };
        let _scope = {
            match modified_scope {
                enums::Scope::Unchanged  => enums::Scope::Unchanged,
                enums::Scope::Changed    => enums::Scope::Changed,
                enums::Scope::NotDefined => panic!("Scope is not defined")
            }
        };

        // Determine whether the unmodified weights should be used
        let attack_vector_weight       = match self.modified_attack_vector {
            enums::AttackVector::NotDefined => self.attack_vector.get_weight(),
            _ => self.modified_attack_vector.get_weight()
        };
        let attack_complexity_weight   = match self.modified_attack_complexity {
            enums::AttackComplexity::NotDefined => self.attack_complexity.get_weight(),
            _ => self.modified_attack_complexity.get_weight()
        };
        let privileges_required_weight = match self.modified_privileges_required {
            enums::PrivilegesRequired::NotDefined => self.privileges_required.get_weight(_scope),
            _ => self.modified_privileges_required.get_weight(_scope)
        };
        let user_interaction_weight    = match self.modified_user_interaction {
            enums::UserInteraction::NotDefined => self.user_interaction.get_weight(),
            _ => self.modified_user_interaction.get_weight()
        };

        8.22 * attack_vector_weight * attack_complexity_weight * privileges_required_weight
        * user_interaction_weight
    }

    pub fn environmental_score(&self) -> f32 {
        let impact_sub_score             = self.modified_impact_sub_score();
        let exploitability_sub_score     = self.modified_exploitability_sub_score();
        let exploit_code_maturity_weight = self.exploit_code_maturity.get_weight();
        let remediation_level_weight     = self.remediation_level.get_weight();
        let report_confidence_weight     = self.report_confidence.get_weight();

        if impact_sub_score <= 0.0 {
            return 0.0;
        }
        else {
            let modified_scope = match self.modified_scope {
                enums::Scope::NotDefined => &self.scope,
                _ => &self.modified_scope
            };
            match modified_scope {
                enums::Scope::Unchanged =>
                    (((impact_sub_score + exploitability_sub_score).min(10.0))
                                                                   .round_up(1)
                    * exploit_code_maturity_weight
                    * remediation_level_weight
                    * report_confidence_weight).round_up(1),
                enums::Scope::Changed =>
                    (((1.08 * (impact_sub_score + exploitability_sub_score)).min(10.0))
                                                                            .round_up(1)
                    * exploit_code_maturity_weight
                    * remediation_level_weight
                    * report_confidence_weight).round_up(1),
                enums::Scope::NotDefined => panic!("Scope is not defined")
            }
        }
    }
}

trait FromVectorString {
    fn from_vector_string(vector_string: &'static str) -> CVSSv3;
}

impl FromVectorString for CVSSv3 {
    fn from_vector_string(vector_string: &'static str) -> CVSSv3 {
        if !vector_string.starts_with("CVSS:3.0/") {
            panic!("Vector string must start with \"CVSS:3.0/\"");
        }

        let mut constructed_cvssv3 = CVSSv3 {
            ..Default::default()
        };

        let vector_string_without_prefix = vector_string.replace("CVSS:3.0/", "");
        let metrics: Vec<String> = vector_string_without_prefix.split('/')
                                                               .map(String::from)
                                                               .collect();
        for metric in metrics {
            let metric_parts: Vec<String> = metric.split(':')
                                                  .map(String::from)
                                                  .collect();
            let metric_name = metric_parts[0].to_string();
            let metric_value = metric_parts[1].to_string();

            if metric_name == "AV" {
                if metric_value == "X" {
                    constructed_cvssv3.attack_vector = enums::AttackVector::NotDefined;
                }
                else {
                    constructed_cvssv3.attack_vector = enums::AttackVector::match_metric_value(&metric_value);
                }
            }
            if metric_name == "AC" {
                if metric_value == "X" {
                    constructed_cvssv3.attack_complexity = enums::AttackComplexity::NotDefined;
                }
                else {
                    constructed_cvssv3.attack_complexity = enums::AttackComplexity::match_metric_value(&metric_value);
                }
            }
            if metric_name == "PR" {
                if metric_value == "X" {
                    constructed_cvssv3.privileges_required = enums::PrivilegesRequired::NotDefined;
                }
                else {
                    constructed_cvssv3.privileges_required = enums::PrivilegesRequired::match_metric_value(&metric_value);
                }
            }
            if metric_name == "UI" {
                if metric_value == "X" {
                    constructed_cvssv3.user_interaction = enums::UserInteraction::NotDefined;
                }
                else {
                    constructed_cvssv3.user_interaction = enums::UserInteraction::match_metric_value(&metric_value);
                }
            }
            if metric_name == "S" {
                if metric_value == "X" {
                    constructed_cvssv3.scope = enums::Scope::NotDefined;
                }
                else {
                    constructed_cvssv3.scope = enums::Scope::match_metric_value(&metric_value);
                }
            }
            if metric_name == "C" {
                if metric_value == "X" {
                    constructed_cvssv3.confidentiality_impact = enums::Impact::NotDefined;
                }
                else {
                    constructed_cvssv3.confidentiality_impact = enums::Impact::match_metric_value(&metric_value);
                }
            }
            if metric_name == "I" {
                if metric_value == "X" {
                    constructed_cvssv3.integrity_impact = enums::Impact::NotDefined;
                }
                else {
                    constructed_cvssv3.integrity_impact = enums::Impact::match_metric_value(&metric_value);
                }
            }
            if metric_name == "A" {
                if metric_value == "X" {
                    constructed_cvssv3.availability_impact = enums::Impact::NotDefined;
                }
                else {
                    constructed_cvssv3.availability_impact = enums::Impact::match_metric_value(&metric_value);
                }
            }
            if metric_name == "E" {
                if metric_value == "X" {
                    constructed_cvssv3.exploit_code_maturity = enums::ExploitCodeMaturity::NotDefined;
                }
                else {
                    constructed_cvssv3.exploit_code_maturity = enums::ExploitCodeMaturity::match_metric_value(&metric_value);
                }
            }
            if metric_name == "RL" {
                if metric_value == "X" {
                    constructed_cvssv3.remediation_level = enums::RemediationLevel::NotDefined;
                }
                else {
                    constructed_cvssv3.remediation_level = enums::RemediationLevel::match_metric_value(&metric_value);
                }
            }
            if metric_name == "RC" {
                if metric_value == "X" {
                    constructed_cvssv3.report_confidence = enums::ReportConfidence::NotDefined;
                }
                else {
                    constructed_cvssv3.report_confidence = enums::ReportConfidence::match_metric_value(&metric_value);
                }
            }
            if metric_name == "CR" {
                if metric_value == "X" {
                    constructed_cvssv3.confidentiality_requirement = enums::SecurityRequirement::NotDefined;
                }
                else {
                    constructed_cvssv3.confidentiality_requirement = enums::SecurityRequirement::match_metric_value(&metric_value);
                }
            }
            if metric_name == "IR" {
                if metric_value == "X" {
                    constructed_cvssv3.integrity_requirement = enums::SecurityRequirement::NotDefined;
                }
                else {
                    constructed_cvssv3.integrity_requirement = enums::SecurityRequirement::match_metric_value(&metric_value);
                }
            }
            if metric_name == "AR" {
                if metric_value == "X" {
                    constructed_cvssv3.availability_requirement = enums::SecurityRequirement::NotDefined;
                }
                else {
                    constructed_cvssv3.availability_requirement = enums::SecurityRequirement::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MAV" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_attack_vector = enums::AttackVector::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_attack_vector = enums::AttackVector::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MAC" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_attack_complexity = enums::AttackComplexity::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_attack_complexity = enums::AttackComplexity::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MPR" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_privileges_required = enums::PrivilegesRequired::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_privileges_required = enums::PrivilegesRequired::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MUI" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_user_interaction = enums::UserInteraction::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_user_interaction = enums::UserInteraction::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MS" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_scope = enums::Scope::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_scope = enums::Scope::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MC" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_confidentiality_impact = enums::Impact::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_confidentiality_impact = enums::Impact::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MI" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_integrity_impact = enums::Impact::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_integrity_impact = enums::Impact::match_metric_value(&metric_value);
                }
            }
            if metric_name == "MA" {
                if metric_value == "X" {
                    constructed_cvssv3.modified_availability_impact = enums::Impact::NotDefined;
                }
                else {
                    constructed_cvssv3.modified_availability_impact = enums::Impact::match_metric_value(&metric_value);
                }
            }
        }
        constructed_cvssv3
    }
}

trait RoundUp {
    fn round_up(&self, decimals: u8) -> f32;
}

impl RoundUp for f32 {
    fn round_up(&self, decimals: u8) -> f32 {
        let multiplier = 10f32.powf(decimals.into());
        (*self * multiplier).ceil() / multiplier
    }
}

#[test]
fn test_round_up() {
    assert_eq!(1.05.round_up(1), 1.1);
    assert_eq!(1.05.round_up(2), 1.05);
    assert_eq!(1.05.round_up(3), 1.050);
    assert_eq!(1.1142.round_up(1), 1.2);
    assert_eq!(1.1142.round_up(2), 1.12);
    assert_eq!(1.1142.round_up(3), 1.115);
    assert_eq!(1.1142.round_up(4), 1.1142);
    assert_eq!(1.1142.round_up(0), 2.0);
    assert_eq!(1.0.round_up(0), 1.0);
    assert_eq!(1.0.round_up(1), 1.0);
    assert_eq!(1.0.round_up(2), 1.00);
}

#[test]
fn test_to_vector_string() {
    let _test = CVSSv3 {
        attack_vector:          enums::AttackVector::Local,
        attack_complexity:      enums::AttackComplexity::Low,
        privileges_required:    enums::PrivilegesRequired::Low,
        user_interaction:       enums::UserInteraction::None,
        scope:                  enums::Scope::Changed,
        confidentiality_impact: enums::Impact::None,
        integrity_impact:       enums::Impact::Low,
        availability_impact:    enums::Impact::High,
        exploit_code_maturity:  enums::ExploitCodeMaturity::Unproven,
        modified_scope:         enums::Scope::Unchanged,
        remediation_level:      enums::RemediationLevel::OfficialFix,
        modified_user_interaction: enums::UserInteraction::Required,
        ..Default::default()
    };

    assert_eq!(_test.to_vector_string(true), "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:X/MA:X");
    assert_eq!(_test.to_vector_string(false), "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/MUI:R/MS:U");
}

#[test]
fn test_from_vector_string() {
    let c = CVSSv3::from_vector_string("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/MUI:R/MS:U");
    assert_eq!(c.base_score(), 7.3);
    assert_eq!(c.temporal_score(), 6.4);
    assert_eq!(c.environmental_score(), 4.9);
    assert_eq!(c.to_vector_string(false), "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/MUI:R/MS:U");
    assert_eq!(c.to_vector_string(true), "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:X/MA:X");

    let c = CVSSv3::from_vector_string("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:X/MA:X");
    assert_eq!(c.base_score(), 7.3);
    assert_eq!(c.temporal_score(), 6.4);
    assert_eq!(c.environmental_score(), 4.9);
    assert_eq!(c.to_vector_string(false), "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/MUI:R/MS:U");
    assert_eq!(c.to_vector_string(true), "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H/E:U/RL:O/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:R/MS:U/MC:X/MI:X/MA:X");
}
