//! Direct-mode bootstrap: create / join / leave / upgrade + AUTH post-auth.

use std::net::Ipv4Addr;

use anyhow::Context;
use clap::Args;
use tunnet_core::direct::admin::{PendingJoin, push_pending};
use tunnet_core::direct::{
    AUTH_ALPN, AuthClientMode, ConnectivityOptions, ConnectivityProfile, DocsMembership,
    MemberRole, MembershipEntry, NetworkGrant, apply_connectivity, decode_invite, derive_ipv4,
    endpoint_builder, generate_coordinator_keypair, load_approved, network_id_from_topic,
    run_auth_client, save_approved, sign_grant, topic_from_name_secret,
};
use tunnet_core::{
    AgentIdentity, DirectState, PersistedState, SealPolicy, StatePaths, load_agent, persist_agent,
};

#[derive(Args, Debug)]
pub struct CreateArgs {
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    /// Auto-admit peers with a valid invite (no manual approval queue).
    #[arg(long)]
    pub open: bool,
    /// Network name (default: direct).
    #[arg(long = "name")]
    pub network_name: Option<String>,
    /// Shared passphrase for this network.
    /// If omitted, a random secret is generated and printed.
    #[arg(long)]
    pub secret: Option<String>,
    /// Store secrets in plaintext (no TPM/Keychain/derived seal).
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct JoinArgs {
    pub invite_code: String,
    #[arg(long, env = "TUNNET_HOSTNAME")]
    pub hostname: Option<String>,
    /// Automatically accept coordinator firewall policy suggestions.
    #[arg(long)]
    pub auto_accept_firewall: bool,
    /// Store secrets in plaintext (no TPM/Keychain/derived seal).
    #[arg(long, env = "TUNNET_NO_ENCRYPT_STATE")]
    pub no_encrypt_state: bool,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    #[arg(
        long,
        env = "CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub control_url: String,
    #[arg(long, env = "TUNNET_ENROLL_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args, Debug)]
pub struct LeaveArgs {
    /// Network name to leave
    #[arg(long)]
    pub network: Option<String>,
    pub name: Option<String>,
}

fn paths(state_dir: Option<&str>) -> StatePaths {
    StatePaths::resolve(state_dir)
}

fn hostname_arg(explicit: Option<String>) -> String {
    explicit
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "tunnet-node".into())
}

async fn write_post_auth_response(
    send: &mut iroh::endpoint::SendStream,
    resp: &[u8],
) -> anyhow::Result<()> {
    let len = (resp.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(resp).await?;
    send.finish()?;
    // Ensure the peer can finish reading before this connection is torn down.
    let _ = send.stopped().await;
    Ok(())
}

fn post_auth_deny(reason: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "accepted": false,
        "reason": reason,
        "status": "denied",
    }))
    .unwrap_or_else(|_| b"{\"accepted\":false,\"reason\":\"internal\"}".to_vec())
}

#[allow(clippy::too_many_arguments)]
pub async fn try_handle_post_auth(
    conn: &iroh::endpoint::Connection,
    state_dir: &std::path::Path,
    docs: Option<&DocsMembership>,
    self_endpoint_id: &str,
    network_id: uuid::Uuid,
    auth: &tunnet_core::direct::auth::AuthCache,
    routes: &tunnet_core::RoutingTable,
    acl: &tunnet_core::AclEngine,
) -> anyhow::Result<()> {
    let paths = StatePaths {
        dir: state_dir.to_path_buf(),
    };
    let policy = SealPolicy::from_env_and_flag(false);

    // Client opens a bi after PSK; wait briefly.
    let (mut send, mut recv) =
        match tokio::time::timeout(std::time::Duration::from_secs(5), conn.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => anyhow::bail!("accept post-auth stream: {e}"),
            Err(_) => anyhow::bail!("timed out waiting for post-auth stream from peer"),
        };

    let Ok((_identity, persisted, _)) = load_agent(&paths, policy) else {
        write_post_auth_response(&mut send, &post_auth_deny("coordinator_state_unavailable"))
            .await?;
        return Ok(());
    };
    let Some(direct) = persisted.direct_by_id(network_id) else {
        write_post_auth_response(&mut send, &post_auth_deny("unknown_network")).await?;
        return Ok(());
    };

    let mut len_buf = [0u8; 4];
    if let Err(e) = recv.read_exact(&mut len_buf).await {
        write_post_auth_response(&mut send, &post_auth_deny("bad_request"))
            .await
            .ok();
        anyhow::bail!("read post-auth length: {e}");
    }
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 64 * 1024 {
        write_post_auth_response(&mut send, &post_auth_deny("request_too_large")).await?;
        anyhow::bail!("post-auth request too large");
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;

    let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let msg_type = req.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let resp = match msg_type {
        "join_request" if direct.coordinator => {
            handle_join_request_bytes(&paths, direct, docs, auth, routes, acl, &body).await?
        }
        "join_request" => post_auth_deny("not_coordinator"),
        "connect_request" => {
            let allowlist = tunnet_core::direct::connect::load_allowlist_from_dir(state_dir);
            let (_accepted, resp_bytes) = tunnet_core::direct::connect::handle_inbound_connect(
                state_dir,
                &format!("{}", conn.remote_id()),
                &body,
                &allowlist,
                &direct.hostname,
                direct.assigned_ipv4,
            )
            .await?;
            let _ = self_endpoint_id;
            resp_bytes
        }
        "connect_accepted" => {
            // Peer notified us they accepted; install route if present.
            if let (Some(ipv4), Some(hostname)) = (
                req.get("ipv4").and_then(|v| v.as_str()),
                req.get("hostname").and_then(|v| v.as_str()),
            ) {
                tracing::info!(%hostname, %ipv4, "remote accepted connect");
            }
            return Ok(());
        }
        _ => post_auth_deny("unknown_request"),
    };

    write_post_auth_response(&mut send, &resp).await?;
    Ok(())
}

pub async fn run_create(args: CreateArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;
    let existing = PersistedState::try_load(&paths)?;
    if let Some(PersistedState::Managed(m)) = &existing {
        anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        );
    }
    let had_networks =
        matches!(&existing, Some(PersistedState::Direct { networks }) if !networks.is_empty());

    let hostname = hostname_arg(args.hostname);
    let network_name = args
        .network_name
        .unwrap_or_else(|| "direct".into())
        .to_ascii_lowercase();
    if !tunnet_common::validate_network_name(&network_name) {
        anyhow::bail!("invalid network name (3-32 lowercase alphanumeric/hyphen)");
    }

    let join_secret = match args.secret {
        Some(s) => {
            if s.len() < 8 {
                anyhow::bail!("--secret must be at least 8 characters");
            }
            hex::encode(s.as_bytes())
        }
        None => {
            let secret_bytes: [u8; 32] = rand::random();
            let s = hex::encode(secret_bytes);
            println!("Generated join secret (save it): {s}");
            s
        }
    };

    let (coord_sk, coord_vk) = generate_coordinator_keypair();
    let coord_vk_hex = hex::encode(coord_vk.to_bytes());
    let coord_sk_hex = hex::encode(coord_sk.to_bytes());
    let content_key = hex::encode(rand::random::<[u8; 32]>());

    let topic_hash = topic_from_name_secret(&network_name, &join_secret);
    let network_id = network_id_from_topic(&topic_hash);
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);

    let (identity, mut networks) = match existing {
        Some(PersistedState::Direct { networks }) => {
            let (identity, _, _) = load_agent(&paths, policy)?;
            if networks
                .iter()
                .any(|d| d.network_name.eq_ignore_ascii_case(&network_name))
            {
                anyhow::bail!("already joined Direct network '{network_name}'");
            }
            if networks.iter().any(|d| d.network_id == network_id) {
                anyhow::bail!("network id collision with an existing Direct network");
            }
            (identity, networks)
        }
        _ => (AgentIdentity::generate(), Vec::new()),
    };
    let my_id = identity.endpoint_id_hex();
    let assigned_ipv4 = derive_ipv4(&my_id, 0);

    let network_id_for_grant = network_id;
    let self_grant = sign_grant(
        &coord_sk,
        NetworkGrant {
            network_id: network_id_for_grant,
            endpoint_id: my_id.clone(),
            role: MemberRole::Coordinator,
            network_epoch: 0,
            issued_at: jiff::Timestamp::now(),
            expires_at: jiff::Timestamp::now()
                .checked_add(jiff::SignedDuration::from_secs(3650 * 86400))?,
            content_key: content_key.clone(),
            sig: String::new(),
        },
    )?;
    let grant_json = serde_json::to_string(&self_grant)?;

    networks.push(DirectState {
        network_name: network_name.clone(),
        join_secret: join_secret.clone(),
        topic_hash,
        network_id,
        coordinator: true,
        open: args.open,
        assigned_ipv4,
        collision_index: 0,
        hostname: hostname.clone(),
        coordinator_endpoint_id: Some(my_id.clone()),
        coordinator_verifying_key: Some(coord_vk_hex),
        network_epoch: 0,
        doc_ticket: None,
        namespace_id: None,
        coordinator_signing_key: Some(coord_sk_hex),
        network_grant: Some(grant_json),
        content_key: Some(content_key),
        auto_accept_firewall: false,
        created_at: jiff::Timestamp::now(),
    });
    let persisted = PersistedState::Direct { networks };
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    {
        use tunnet_core::TunnetConfig;
        let mut cfg = TunnetConfig::from_persisted(&paths)?;
        cfg.upsert_direct(&network_name, &hostname, args.open, false);
        cfg.save(&paths)?;
    }

    println!(
        "Created Direct network '{}'. endpoint_id={} ip={} (secrets: {})",
        network_name,
        my_id,
        assigned_ipv4,
        tier.as_str()
    );
    println!("State directory: {}", paths.dir.display());
    crate::cmds::finish_after_config(state_dir, had_networks).await?;
    println!("Next: `tunnet invite` and share the code.");
    Ok(())
}
pub async fn run_join(args: JoinArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    paths.ensure()?;

    let invite = decode_invite(&args.invite_code)?;
    let hostname = hostname_arg(args.hostname);
    let policy = SealPolicy::from_env_and_flag(args.no_encrypt_state);
    let network_id = network_id_from_topic(&invite.topic);
    let network_name = invite.network_name.clone();

    let loaded = PersistedState::try_load(&paths)?;
    let had_networks =
        matches!(&loaded, Some(PersistedState::Direct { networks }) if !networks.is_empty());
    let (identity, existing_networks) = match loaded {
        Some(PersistedState::Managed(m)) => anyhow::bail!(
            "already enrolled in Managed network '{}'; run `tunnet reset --yes` first",
            m.network_name
        ),
        Some(PersistedState::Direct { networks }) => {
            if networks
                .iter()
                .any(|d| d.network_name.eq_ignore_ascii_case(&network_name))
            {
                anyhow::bail!("already joined Direct network '{network_name}'");
            }
            if networks.iter().any(|d| d.network_id == network_id) {
                anyhow::bail!("already joined this Direct network id");
            }
            let (id, _, _) = load_agent(&paths, policy)?;
            (id, networks)
        }
        None => (AgentIdentity::generate(), Vec::new()),
    };

    let my_id = identity.endpoint_id_hex();
    let mut collision_index = 0u8;
    let mut assigned_ipv4 = derive_ipv4(&my_id, collision_index);

    // Dial coordinator and prove PSK.
    let secret = iroh::SecretKey::from_bytes(&identity.secret_bytes);
    let connectivity = ConnectivityOptions {
        profile: ConnectivityProfile::ServerlessDht,
        enable_mdns: false,
        custom_relays: Vec::new(),
        relay_fallback: tunnet_common::ConnectivityRelayFallback::N0,
    };
    let endpoint = apply_connectivity(
        endpoint_builder(&connectivity)
            .secret_key(secret)
            .alpns(vec![AUTH_ALPN.to_vec()]),
        &connectivity,
    )
    .bind()
    .await
    .context("bind join endpoint")?;

    let join_result = async {
        match tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online()).await {
            Ok(()) => tracing::info!("join endpoint online"),
            Err(_) => tracing::warn!("relay not ready yet; attempting join connect anyway"),
        }

        let coord: iroh::EndpointId = invite
            .coordinator
            .parse()
            .context("invalid coordinator endpoint id in invite")?;
        let conn = endpoint
            .connect(coord, AUTH_ALPN)
            .await
            .context("connect to coordinator")?;
        run_auth_client(
            &conn,
            AuthClientMode::Invite {
                network_id,
                invite_id: invite.invite_id.clone(),
                join_secret_hex: invite.join_secret.clone(),
            },
            &my_id,
        )
        .await
        .context("invite auth with coordinator")?;

        // Send join request over the same connection.
        let (mut send, mut recv) = conn.open_bi().await.context("open join stream")?;
        let req = serde_json::json!({
            "type": "join_request",
            "endpoint_id": my_id,
            "hostname": hostname,
            "ipv4": assigned_ipv4.to_string(),
            "collision_index": collision_index,
            "invite_id": invite.invite_id,
            "reusable": invite.reusable,
        });
        let bytes = serde_json::to_vec(&req)?;
        let len = (bytes.len() as u32).to_be_bytes();
        send.write_all(&len).await.context("write join request")?;
        send.write_all(&bytes).await.context("write join request")?;
        send.finish().context("finish join request")?;

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .context("read join response (is the coordinator agent running `tunnetd`?)")?;
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        recv.read_exact(&mut body)
            .await
            .context("read join response body")?;
        let resp: serde_json::Value = serde_json::from_slice(&body)?;
        if resp.get("accepted").and_then(|v| v.as_bool()) != Some(true) {
            let reason = resp
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("denied");
            anyhow::bail!("join denied: {reason}");
        }
        if let Some(ip) = resp.get("ipv4").and_then(|v| v.as_str()) {
            assigned_ipv4 = ip.parse().unwrap_or(assigned_ipv4);
        }
        if let Some(ci) = resp.get("collision_index").and_then(|v| v.as_u64()) {
            collision_index = ci as u8;
        }
        let doc_ticket = resp
            .get("doc_ticket")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .context(
                "coordinator did not return a doc_ticket (is `tunnetd` up on the coordinator?)",
            )?;
        let network_grant = resp
            .get("network_grant")
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .filter(|s| !s.is_empty());
        let content_key = resp
            .get("content_key")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok::<_, anyhow::Error>((doc_ticket, network_grant, content_key))
    }
    .await;

    endpoint.close().await;
    let (doc_ticket, network_grant, content_key) = join_result?;

    let mut networks = existing_networks;
    networks.push(DirectState {
        network_name: network_name.clone(),
        join_secret: invite.join_secret,
        topic_hash: invite.topic,
        network_id,
        coordinator: false,
        open: false,
        assigned_ipv4,
        collision_index,
        hostname: hostname.clone(),
        coordinator_endpoint_id: Some(invite.coordinator),
        coordinator_verifying_key: Some(invite.coordinator_verifying_key),
        network_epoch: 0,
        doc_ticket: Some(doc_ticket),
        namespace_id: None,
        coordinator_signing_key: None,
        network_grant,
        content_key,
        auto_accept_firewall: args.auto_accept_firewall,
        created_at: jiff::Timestamp::now(),
    });
    let persisted = PersistedState::Direct { networks };
    let tier = persist_agent(&paths, &identity, persisted, policy)?;
    {
        use tunnet_core::TunnetConfig;
        let mut cfg = TunnetConfig::from_persisted(&paths)?;
        cfg.upsert_direct(&network_name, &hostname, false, false);
        cfg.save(&paths)?;
    }

    println!(
        "Joined Direct network '{}'. endpoint_id={} ip={} (secrets: {})",
        network_name,
        my_id,
        assigned_ipv4,
        tier.as_str()
    );
    crate::cmds::finish_after_config(state_dir, had_networks).await?;
    Ok(())
}
/// Coordinator-side: handle join over AUTH connection (called from accept loop).
/// Requires a live [`DocsMembership`] to issue a write ticket.
pub async fn handle_join_request_bytes(
    paths: &StatePaths,
    direct: &DirectState,
    docs: Option<&DocsMembership>,
    auth: &tunnet_core::direct::auth::AuthCache,
    routes: &tunnet_core::RoutingTable,
    acl: &tunnet_core::AclEngine,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let req: serde_json::Value = serde_json::from_slice(body)?;
    let endpoint_id = req
        .get("endpoint_id")
        .and_then(|v| v.as_str())
        .context("endpoint_id")?
        .to_string();
    let hostname = req
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("peer")
        .to_string();
    let ipv4: Ipv4Addr = req
        .get("ipv4")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0.0")
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let collision_index = req
        .get("collision_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;
    let invite_id = req
        .get("invite_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let reusable = req
        .get("reusable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let approved = load_approved(paths).unwrap_or_default();
    let pre_approved = approved.iter().any(|id| id == &endpoint_id);

    let issued =
        tunnet_core::direct::admin::load_invite_ids(paths, direct.network_id).unwrap_or_default();
    let invite_ok = invite_id.as_ref().is_some_and(|id| issued.contains(id));

    if !direct.open && !pre_approved && !invite_ok {
        if invite_id.is_some() {
            return Ok(serde_json::to_vec(&serde_json::json!({
                "accepted": false,
                "reason": "invalid_or_used_invite",
            }))?);
        }
        push_pending(
            paths,
            direct.network_id,
            &PendingJoin {
                endpoint_id: endpoint_id.clone(),
                hostname: hostname.clone(),
                ipv4,
                collision_index,
            },
        )?;
        return Ok(serde_json::to_vec(&serde_json::json!({
            "accepted": false,
            "reason": "pending_approval",
        }))?);
    }

    let Some(docs) = docs else {
        return Ok(serde_json::to_vec(&serde_json::json!({
            "accepted": false,
            "reason": "coordinator_docs_not_ready",
        }))?);
    };

    let members = docs.snapshot_members();
    let mut ci = collision_index;
    let mut ip = if ipv4.is_unspecified() {
        derive_ipv4(&endpoint_id, ci)
    } else {
        ipv4
    };
    while members
        .iter()
        .any(|m| m.ipv4 == ip && m.endpoint_id != endpoint_id)
    {
        ci = ci.saturating_add(1);
        ip = derive_ipv4(&endpoint_id, ci);
    }

    let entry = MembershipEntry {
        endpoint_id: endpoint_id.clone(),
        hostname: hostname.clone(),
        ipv4: ip,
        collision_index: ci,
        tags: vec![],
        joined_at: jiff::Timestamp::now(),
        coordinator: false,
        status: "active".into(),
        ssh_host_key: None,
    };
    let (grant, content_key) = docs.admit_peer(&entry, auth).await?;
    docs.refresh_seed_peers();
    let policy = (**acl.bundle.load()).clone();
    docs.apply_to_routes(routes, acl, &policy);
    let ticket = docs.share_read_ticket().await?;

    // Drop from approved list once ticket issued.
    if pre_approved {
        let mut ids = approved;
        ids.retain(|id| id != &endpoint_id);
        let _ = save_approved(paths, &ids);
    }

    // Consume one-time invites after a successful ticket issue.
    if !reusable && let Some(id) = invite_id.as_ref() {
        let mut ids = issued;
        ids.remove(id);
        let _ = tunnet_core::direct::admin::save_invite_ids(paths, direct.network_id, &ids);
    }

    let _ = (hostname,);
    Ok(serde_json::to_vec(&serde_json::json!({
        "accepted": true,
        "ipv4": ip.to_string(),
        "collision_index": ci,
        "doc_ticket": ticket,
        "network_grant": grant,
        "content_key": content_key,
    }))?)
}
pub async fn run_upgrade(args: UpgradeArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let (identity, persisted, _) = load_agent(&paths, policy)?;
    let direct = persisted.require_direct_network(None)?.clone();
    if !direct.coordinator {
        anyhow::bail!("only the coordinator should run upgrade-to-managed first");
    }

    // Prefer live docs cache if present from a previous run; else empty members list.
    let members_path = paths.dir.join("direct_members_cache.json");
    let members: Vec<MembershipEntry> = if members_path.exists() {
        serde_json::from_slice(&std::fs::read(&members_path)?).unwrap_or_default()
    } else {
        vec![]
    };

    let token = args
        .token
        .context("provide --token <enrollment token> from the dashboard")?;

    let import = serde_json::json!({
        "direct_network_name": direct.network_name,
        "topic_hash": direct.topic_hash,
        "namespace_id": direct.namespace_id,
        "members": members,
        "coordinator_endpoint_id": identity.endpoint_id_hex(),
    });

    let client = tunnet_core::UnauthedClient::new(args.control_url.clone())?;
    let meta =
        crate::system_info::collect_system_metadata(&direct.hostname, env!("CARGO_PKG_VERSION"));
    let resp = client
        .enroll(tunnet_common::EnrollRequest {
            enrollment_token: Some(token.clone()),
            organization_slug: None,
            network_id: None,
            network_name: Some(direct.network_name.clone()),
            endpoint_id: identity.endpoint_id_hex(),
            hostname: direct.hostname.clone(),
            os: std::env::consts::OS.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata: Some(serde_json::json!({
                "direct_upgrade": import,
                "system": meta,
            })),
            labels: None,
            expires_in: None,
        })
        .await
        .context("enroll into Managed during upgrade")?;

    if resp.status == "pending" {
        anyhow::bail!("upgrade enroll is pending approval; approve in the dashboard then re-run");
    }

    let managed = PersistedState::Managed(tunnet_core::ManagedState {
        control_url: args.control_url.clone(),
        network_name: resp.network_name.clone(),
        network_id: resp.network_id,
        organization_id: resp.organization_id,
        enrolled_at: jiff::Timestamp::now(),
        management_url: None,
        dashboard_url: None,
        local_ui: tunnet_common::local_api::LocalUiPolicy::default(),
    });
    persist_agent(&paths, &identity, managed, policy)?;
    tunnet_core::state::save_snapshot_cache(&paths, &resp.snapshot)?;

    let notice = serde_json::json!({
        "type": "upgrade_to_managed",
        "control_url": args.control_url,
        "enrollment_token": token,
        "network_id": resp.network_id,
        "network_name": resp.network_name,
    });
    std::fs::write(
        paths.dir.join("upgrade_notice.json"),
        serde_json::to_vec_pretty(&notice)?,
    )?;

    println!(
        "Upgraded to Managed network '{}'. Restart with `tunnetd`. \
         Peers should pick up the upgrade notice or re-enroll with the same token.",
        resp.network_name
    );
    Ok(())
}

pub async fn run_leave(args: LeaveArgs, state_dir: Option<&str>) -> anyhow::Result<()> {
    let paths = paths(state_dir);
    let policy = SealPolicy::from_env_and_flag(false);
    let name = args.network.or(args.name);
    let nname = tunnet_core::leave_direct_network(&paths, policy, name.as_deref())?;
    println!("Left Direct network '{nname}'. Restart the agent to apply.");
    crate::cmds::finish_after_config(state_dir, true).await?;
    Ok(())
}
