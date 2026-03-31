mod patterns;
use patterns::abstracts::InjectionAnalysis;
use patterns::main::{audit_patterns, matched_patterns};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

pub fn is_query_malicious(query: &str) -> bool {
    let matches = matched_patterns(query);
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
    dict.set_item(
        "affected_databases",
        PyList::new(
            py,
            analysis
                .affected_databases
                .iter()
                .map(|db| db.as_str())
                .collect::<Vec<_>>(),
        )?,
    )?;

    Ok(dict.into())
}

#[pymodule]
fn sqlhund(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_is_query_malicious, m)?)?;
    m.add_function(wrap_pyfunction!(py_analyze_query, m)?)?;
    Ok(())
}
