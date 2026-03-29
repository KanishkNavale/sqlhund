mod patterns;
use patterns::matched_patterns;

use pyo3::prelude::*;

pub fn validate_query(query: &str) -> bool {
    let matches = matched_patterns(query);
    !matches.is_empty()
}

#[pyfunction]
#[pyo3(name = "validate_query")]
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
///     >>> injectdb.validate_query("' OR 1=1 --")
///     True
///     >>> injectdb.validate_query("SELECT id FROM users WHERE id = 1")
///     False
fn py_validate_query(query: &str) -> PyResult<bool> {
    Ok(validate_query(query))
}

#[pymodule]
fn injectdb(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_validate_query, m)?)?;
    Ok(())
}
