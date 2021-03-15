//! Protocol session
//! Defines role pre-session and session and their respective parameters

use crate::role::Role;

pub mod client;
pub mod daemon;

pub struct PreSession<R>
where
    R: Role + PreSessionParameters,
{
    pub parameters: R::PreSessionParameters,
}

impl<R> PreSession<R>
where
    R: Role + PreSessionParameters,
{
    pub fn new(parameters: R::PreSessionParameters) -> Self {
        Self { parameters }
    }

    pub fn get_params(&self) -> &R::PreSessionParameters {
        &self.parameters
    }
}

impl<R> PreSession<R> 
where
    R: Role + PreSessionParameters + Parameters,
{
    pub fn into_session(&self, session_params: R::Parameters) -> Session<R> {
        Session::<R>::new(self.get_params().clone(), session_params)
    }
}

pub trait PreSessionParameters {
    type PreSessionParameters: Clone;
}

pub struct Session<R>
where
    R: Role + PreSessionParameters + Parameters,
{
    pub uuid: String,
    pub pre_session_parameters: R::PreSessionParameters,
    pub parameters: R::Parameters,
}

impl<R> Session<R>
where
    R: Role + PreSessionParameters + Parameters,
{
    /// Generate a new session for a swap role
    pub fn new(
        pre_session_parameters: R::PreSessionParameters,
        parameters: R::Parameters,
    ) -> Self {
        Self {
            uuid: String::from("session id"),
            pre_session_parameters,
            parameters,
        }
    }

    pub fn pre_session_params(&self) -> &R::PreSessionParameters {
        &self.pre_session_parameters
    }

    pub fn get_params(&self) -> &R::Parameters {
        &self.parameters
    }
}

pub trait Parameters {
    type Parameters;
}
