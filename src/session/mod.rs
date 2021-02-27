//! Protocol session
//! Defines role pre-session and session and their respective parameters

use crate::roles::Role;

pub mod client;
pub mod daemon;

pub struct PreSession<R>
where
    R: Role + PreSessionParameters,
{
    pub parameters: <R as PreSessionParameters>::Parameters,
}

impl<R> PreSession<R>
where
    R: Role + PreSessionParameters,
{
    pub fn new(parameters: <R as PreSessionParameters>::Parameters) -> Self {
        PreSession { parameters }
    }

    pub fn get_params(&self) -> &<R as PreSessionParameters>::Parameters {
        &self.parameters
    }
}

impl<R> PreSession<R>
where
    R: Role + PreSessionParameters + SessionParameters,
{
    pub fn into_session(&self, session_params: <R as SessionParameters>::Parameters) -> Session<R> {
        Session::<R>::new(self.get_params().clone(), session_params)
    }
}

pub trait PreSessionParameters {
    type Parameters: Clone;
}

pub struct Session<R>
where
    R: Role + PreSessionParameters + SessionParameters,
{
    pub uuid: String,
    pub pre_session_parameters: <R as PreSessionParameters>::Parameters,
    pub parameters: <R as SessionParameters>::Parameters,
}

impl<R> Session<R>
where
    R: Role + PreSessionParameters + SessionParameters,
{
    /// Generate a new session for a swap role
    pub fn new(
        pre_session_parameters: <R as PreSessionParameters>::Parameters,
        parameters: <R as SessionParameters>::Parameters,
    ) -> Self {
        Session {
            uuid: String::from("session id"),
            pre_session_parameters,
            parameters,
        }
    }

    pub fn pre_session_params(&self) -> &<R as PreSessionParameters>::Parameters {
        &self.pre_session_parameters
    }

    pub fn get_params(&self) -> &<R as SessionParameters>::Parameters {
        &self.parameters
    }
}

pub trait SessionParameters {
    type Parameters;
}
