use async_std::sync::{
    Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use surf::Client;

use crate::{
    gamma::{self, Credentials, User},
    Opt,
};

struct CacheEntry {
    last_checked: Instant,
    login_result: Result<User, String>,
    http_client: Client,
}

pub struct UserCache {
    map: Mutex<HashMap<Credentials, Arc<RwLock<Option<CacheEntry>>>>>,
}

// TODO: Arbitraty cache time, should be configurable
const CACHE_TIME: Duration = Duration::from_secs(10);

impl UserCache {
    pub(crate) fn new() -> Self {
        UserCache {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn login(&self, opt: &Opt, credentials: &Credentials) -> Result<User, String> {
        let mut map = self.map.lock().await;

        // if an entry already exists
        if let Some(user_state) = map.get(credentials) {
            // clone it
            let user_state = Arc::clone(user_state);
            drop(map); // release the map lock

            loop {
                let guard = user_state.read().await;
                let entry = guard.as_ref().expect("already_initialized");

                let last_checked = entry.last_checked;
                // if the entry has not expired
                if last_checked.elapsed() < CACHE_TIME {
                    // take the fast path and just assume we are still logged in
                    break entry.login_result.clone();
                } else {
                    // otherwise try to upgrade to a write lock so that we can refresh the session
                    drop(guard);
                    let mut guard = user_state.write().await;
                    let mut entry = guard.as_mut().expect("already initialized");

                    // if the entry was updated when we didn't have the lock, retry
                    if entry.last_checked != last_checked {
                        continue;
                    }

                    let login_result = gamma::login(&mut entry.http_client, opt, credentials).await;
                    entry.last_checked = Instant::now();
                    entry.login_result = login_result.clone();
                    break login_result;
                }
            }
        } else {
            // if the entry did not exist, then we must log in

            // create an empty lock and take the write handle
            let lock = Arc::new(RwLock::new(None));
            let mut entry = lock.write().await;

            // then put it in the map so that we can release the map as fast as possible
            map.insert(credentials.clone(), Arc::clone(&lock));
            drop(map); // release the map lock

            let mut client = Client::builder()
                .cookie_store(true)
                .timeout(Duration::from_secs(10 /* TODO: configure timeout */))
                .build()
                .expect("http client");

            let login_result = gamma::login(&mut client, opt, credentials).await;
            let last_checked = Instant::now();

            // try to log in and cache the result
            let new_entry = CacheEntry {
                login_result: login_result.clone(),
                last_checked,
                http_client: client,
            };

            *entry = Some(new_entry);

            login_result
        }
    }
}
