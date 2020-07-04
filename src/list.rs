use super::args::ListCommand;
use super::netns::Lockfile;
use super::util::config_dir;
use chrono::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use walkdir::WalkDir;

// TODO: Implement read-only namespace struct without Drop?

pub fn output_list(listcmd: ListCommand) -> anyhow::Result<()> {
    match listcmd.list_type.as_deref() {
        Some("namespaces") => print_namespaces()?,
        _ => print_applications()?,
    }

    Ok(())
}

pub fn print_applications() -> anyhow::Result<()> {
    let namespaces = get_lock_namespaces()?;

    let mut keys = namespaces.keys().collect::<Vec<&String>>();
    keys.sort();

    if !keys.is_empty() {
        println!("namespace\tprovider\tprotocol\tapplication\tuptime");
        let now = Utc::now();
        for ns in keys {
            for lock in namespaces.get(ns).unwrap() {
                let naive = NaiveDateTime::from_timestamp(lock.start as i64, 0);
                let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
                let diff = now - datetime;
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    &ns,
                    &lock.ns.provider,
                    &lock.ns.protocol,
                    &lock.command,
                    compound_duration::format_wdhms(diff.to_std().unwrap().as_secs())
                );
            }
        }
    }
    // Avoid triggering Drop for these namespaces
    let namespaces = Box::new(namespaces);
    Box::leak(namespaces);
    Ok(())
}

// TODO: DRY
pub fn print_namespaces() -> anyhow::Result<()> {
    let namespaces = get_lock_namespaces()?;

    let mut keys = namespaces.keys().collect::<Vec<&String>>();
    keys.sort();

    if !keys.is_empty() {
        let now = Utc::now();
        println!("namespace\tprovider\tprotocol\tnum_applications\tuptime");
        for ns in keys {
            let first_lock = &namespaces.get(ns).as_ref().unwrap()[0];

            let min_time = namespaces
                .get(ns)
                .unwrap()
                .iter()
                .map(|x| x.start)
                .min()
                .unwrap();
            let naive = NaiveDateTime::from_timestamp(min_time as i64, 0);
            let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
            let diff = now - datetime;
            println!(
                "{}\t{}\t{}\t{}\t{}",
                ns,
                first_lock.ns.provider,
                first_lock.ns.protocol,
                namespaces.get(ns).unwrap().len(),
                compound_duration::format_wdhms(diff.to_std().unwrap().as_secs())
            );
        }
    }
    // Avoid triggering Drop for these namespaces
    let namespaces = Box::new(namespaces);
    Box::leak(namespaces);
    Ok(())
}

pub fn get_lock_namespaces() -> anyhow::Result<HashMap<String, Vec<Lockfile>>> {
    let mut dir = config_dir()?;
    dir.push("vopono");
    dir.push("locks");

    let mut namespaces: HashMap<String, Vec<Lockfile>> = HashMap::new();
    WalkDir::new(dir)
        .into_iter()
        .filter(|x| x.is_ok() && x.as_ref().unwrap().path().is_file())
        .map(|x| x.unwrap())
        .try_for_each(|x| -> anyhow::Result<()> {
            let lockfile = File::open(x.path())?;
            let lock: Lockfile = ron::de::from_reader(lockfile)?;
            namespaces
                .entry(lock.ns.name.clone())
                .or_insert_with(Vec::new)
                .push(lock);
            Ok(())
        })?;
    Ok(namespaces)
}
