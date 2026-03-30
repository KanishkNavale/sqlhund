mod patterns;
use patterns::matched_patterns;

use pyo3::prelude::*;

pub fn is_query_malicious(query: &str) -> bool {
    let matches = matched_patterns(query);
    !matches.is_empty()
}

#[pyfunction]
#[pyo3(name = "is_query_malicious")]
/// Checks whether the input string contains SQL injection patterns.
///
/// Args:
///     query (str): The input string to validate.
///
/// Returns:
///     bool: True if an injection pattern is detected, False otherwise.
///
/// Example:
///     >>> import injectdb
///     >>> injectdb.is_query_malicious("' OR 1=1 --")
///     True
///     >>> injectdb.is_query_malicious("SELECT id FROM users WHERE id = 1")
///     False
fn py_is_query_malicious(query: &str) -> PyResult<bool> {
    Ok(is_query_malicious(query))
}

#[pymodule]
fn injectdb(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_is_query_malicious, m)?)?;
    Ok(())
}
