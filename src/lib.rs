mod patterns;
use patterns::abstracts::InjectionAnalysis;
use patterns::main::{audit_patterns, get_pattern_matches};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

pub fn is_query_malicious(query: &str) -> bool {
    let matches = get_pattern_matches(query);
    !matches.is_empty()
}

pub fn analyze_query(query: &str) -> InjectionAnalysis {
    audit_patterns(query)
}

#[pyfunction]
#[pyo3(name = "is_query_malicious")]
fn py_is_query_malicious(query: &str) -> PyResult<bool> {
    Ok(is_query_malicious(query))
}

#[pyfunction]
#[pyo3(name = "analyze_query")]
fn py_analyze_query(py: Python<'_>, query: &str) -> PyResult<Py<PyDict>> {
    let analysis = analyze_query(query);

    let dict = PyDict::new(py);
    dict.set_item("is_malicious", analysis.is_malicious)?;

    let matches_dict = PyDict::new(py);

    for db_match in analysis.matches {
        let patterns_list = db_match
            .patterns
            .iter()
            .map(|pattern| {
                let pattern_dict = PyDict::new(py);

                let technique_list = PyList::new(
                    py,
                    pattern
                        .technique
                        .iter()
                        .map(|cwe| cwe.as_str())
                        .collect::<Vec<_>>(),
                )?;
                pattern_dict.set_item("technique", technique_list)?;

                let impact_list = PyList::new(
                    py,
                    pattern
                        .impact
                        .iter()
                        .map(|cwe| cwe.as_str())
                        .collect::<Vec<_>>(),
                )?;
                pattern_dict.set_item("impact", impact_list)?;

                let capec_list = PyList::new(py, pattern.capec.to_vec())?;
                pattern_dict.set_item("capec", capec_list)?;

                Ok::<_, PyErr>(pattern_dict)
            })
            .collect::<PyResult<Vec<_>>>()?;

        matches_dict.set_item(db_match.database.as_str(), PyList::new(py, patterns_list)?)?;
    }

    dict.set_item("matches", matches_dict)?;

    Ok(dict.into())
}

#[pymodule]
fn sqlhund(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_is_query_malicious, m)?)?;
    m.add_function(wrap_pyfunction!(py_analyze_query, m)?)?;
    Ok(())
}
