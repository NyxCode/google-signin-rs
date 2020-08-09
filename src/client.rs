use bytes::buf::ext::BufExt;
use hyper::client::{Client as HyperClient, HttpConnector};

#[cfg(feature = "with-openssl")]
use hyper_openssl::HttpsConnector;
#[cfg(feature = "with-rustls")]
use hyper_rustls::HttpsConnector;

use crate::cache_control::CacheControl;
use crate::token::IdInfo;
use crate::Error;
use serde::Deserialize;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const CERTS_URL: &'static str = "https://www.googleapis.com/oauth2/v2/certs";

pub struct Client {
    hyper: HyperClient<HttpsConnector<HttpConnector>>,
    certs: async_mutex::Mutex<CachedCerts>,
    pub audiences: Vec<String>,
    pub hosted_domains: Vec<String>,
}

#[derive(Deserialize)]
struct CertsObject {
    keys: Vec<Cert>,
}

#[derive(Deserialize)]
struct Cert {
    kid: String,
    e: String,
    n: String,
}

#[derive(Default)]
pub struct CachedCerts {
    keys: HashMap<String, Cert>,
    expiry: Option<Instant>,
}

impl CachedCerts {
    async fn refresh_if_needed(&mut self, client: &Client) -> Result<(), Error> {
        if !self.should_refresh() {
            return Ok(());
        }

        let certs = client
            .get_any::<CertsObject>(CERTS_URL, &mut self.expiry)
            .await?;

        self.keys.clear();

        for cert in certs.keys {
            self.keys.insert(cert.kid.clone(), cert);
        }

        Ok(())
    }

    fn should_refresh(&self) -> bool {
        match self.expiry {
            None => true,
            Some(expiry) => expiry <= Instant::now() - Duration::from_secs(10),
        }
    }
}
impl Default for Client {
    fn default() -> Self {
        #[cfg(feature = "with-rustls")]
        let ssl = HttpsConnector::new();
        #[cfg(feature = "with-openssl")]
        let ssl = HttpsConnector::new().expect("unable to build HttpsConnector");

        let client = HyperClient::builder()
            .http1_max_buf_size(0x2000)
            .pool_max_idle_per_host(0)
            .build(ssl);

        Client {
            hyper: client,
            audiences: vec![],
            hosted_domains: vec![],
            certs: Default::default(),
        }
    }
}

impl Client {
    /// Verifies that the token is signed by Google's OAuth cerificate,
    /// and check that it has a valid issuer, audience, and hosted domain.
    /// Returns an error if the client has no configured audiences.
    pub async fn verify(&self, id_token: &str) -> Result<IdInfo, Error> {
        let unverified_header = jsonwebtoken::decode_header(&id_token)?;

        let mut certs = self.certs.lock().await;
        certs.refresh_if_needed(self).await?;

        match unverified_header.kid {
            Some(kid) => {
                let cert = certs.keys.get(&kid).ok_or(Error::InvalidKey)?;
                self.verify_single(id_token, cert)
            }
            None => certs
                .keys
                .values()
                .flat_map(|cert| self.verify_single(id_token, cert))
                .next()
                .ok_or(Error::InvalidToken),
        }
    }

    fn verify_single(&self, id_token: &str, cert: &Cert) -> Result<IdInfo, Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&self.audiences);
        let token_data = jsonwebtoken::decode::<IdInfo>(
            &id_token,
            &DecodingKey::from_rsa_components(&cert.n, &cert.e),
            &validation,
        )?;

        token_data.claims.verify(self)?;

        Ok(token_data.claims)
    }

    async fn get_any<T: DeserializeOwned>(
        &self,
        url: &str,
        cache: &mut Option<Instant>,
    ) -> Result<T, Error> {
        let url = url.parse().unwrap();
        let response = self.hyper.get(url).await.unwrap();

        if !response.status().is_success() {
            return Err(Error::InvalidToken);
        }

        if let Some(value) = response.headers().get("Cache-Control") {
            if let Ok(value) = value.to_str() {
                if let Some(cc) = CacheControl::from_value(value) {
                    if let Some(max_age) = cc.max_age {
                        let seconds = max_age.as_secs();
                        *cache = Some(Instant::now() + Duration::from_secs(seconds as u64));
                    }
                }
            }
        }

        let body = hyper::body::aggregate(response).await?;
        Ok(serde_json::from_reader(body.reader())?)
    }
}
