//! Splunk REST API workflows and the offline clispec contract.
pub mod auth;
pub mod browser;
pub mod cli;
pub mod client;
pub mod config;
pub mod error;
pub mod interrupt;
pub mod output;
pub mod schema;
pub mod workflows;
pub use error::{Error, Result};
