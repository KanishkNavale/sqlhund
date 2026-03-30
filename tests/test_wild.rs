use injectdb::is_query_malicious;

#[cfg(test)]
mod dataset_tests {
    use super::*;
    use indicatif::{ProgressBar, ProgressStyle};

    const DATASET_PATH: &str = "tests/data/wild.csv";
    const OUTPUT_DIR: &str = "tests/output";

    fn load_data() -> Vec<(String, bool)> {
        let mut rdr = csv::Reader::from_path(DATASET_PATH).expect("Failed to open dataset");
        let records: Vec<_> = rdr.records().filter_map(|r| r.ok()).collect();

        let mut true_count = 0;
        let mut false_count = 0;
        let mut unknown_count = 0;

        let data: Vec<(String, bool)> = records
            .into_iter()
            .map(|record| {
                let query = record[0].trim().to_string();
                let raw_label = record[2].trim().to_lowercase();
                let malicious = match raw_label.as_str() {
                    "true" | "1" | "vulnerable" | "malicious" | "sqli" | "union-based"
                    | "boolean-based" | "time-based" | "error-based" | "stackqueries-based"
                    | "meta-based" | "yes" => {
                        true_count += 1;
                        true
                    }
                    "false" | "0" | "not vulnerable" | "benign" | "safe" | "normal" | "no" => {
                        false_count += 1;
                        false
                    }
                    other => {
                        unknown_count += 1;
                        eprintln!("Unknown label: {:?}", other);
                        false
                    }
                };
                (query, malicious)
            })
            .collect();

        println!("\n\n# Dataset Distribution");
        println!("  Malicious (true):  {}", true_count);
        println!("  Benign (false):    {}", false_count);
        println!("  Unknown:           {}", unknown_count);
        println!("  Total:             {}", data.len());

        data
    }

    #[test]
    #[ignore = "Requires the dataset"]
    fn test_is_query_malicious_dataset() {
        let cases = load_data();
        let total = cases.len();
        let mut tp = 0usize;
        let mut tn = 0usize;
        let mut fp = 0usize;
        let mut fn_ = 0usize;
        let mut fp_errors = vec![];
        let mut fn_errors = vec![];

        println!("\n\nValidating {} queries...\n", total);
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:50.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );

        for (query, expected) in &cases {
            let result = is_query_malicious(query);
            match (expected, result) {
                (true, true) => tp += 1,
                (false, false) => tn += 1,
                (false, true) => {
                    fp += 1;
                    fp_errors.push(query.clone());
                }
                (true, false) => {
                    fn_ += 1;
                    fn_errors.push(query.clone());
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message("Validation complete");

        let precision = if tp + fp > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            0.0
        };
        let recall = if tp + fn_ > 0 {
            tp as f64 / (tp + fn_) as f64
        } else {
            0.0
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        let accuracy = if total > 0 {
            (tp + tn) as f64 / total as f64
        } else {
            0.0
        };

        println!("\n\n# Results");
        println!("  True Positives:  {}", tp);
        println!("  True Negatives:  {}", tn);
        println!("  False Positives: {}", fp);
        println!("  False Negatives: {}", fn_);
        println!("\n# Metrics");
        println!("  Accuracy:  {:.4}", accuracy);
        println!("  Precision: {:.4}", precision);
        println!("  Recall:    {:.4}", recall);
        println!("  F1 Score:  {:.4}", f1);

        std::fs::create_dir_all(OUTPUT_DIR).expect("Failed to create output directory");

        if fp > 0 {
            std::fs::write(
                format!("{}/fp_errors.txt", OUTPUT_DIR),
                fp_errors.join("\n"),
            )
            .expect("Failed to write FP errors");
        }

        if fn_ > 0 {
            std::fs::write(
                format!("{}/fn_errors.txt", OUTPUT_DIR),
                fn_errors.join("\n"),
            )
            .expect("Failed to write FN errors");
        }
    }
}
