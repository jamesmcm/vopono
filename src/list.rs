use super::args::ListCommand;
use anyhow::anyhow;
use chrono::prelude::*;
use vopono_core::util::get_lock_namespaces;

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
                let datetime = DateTime::from_timestamp(lock.start as i64, 0)
                    .ok_or_else(|| anyhow!("Timestamp parsing failed"))?;
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
    std::mem::forget(namespaces);
    Ok(())
}

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
            let datetime = DateTime::from_timestamp(min_time as i64, 0)
                .ok_or_else(|| anyhow!("Timestamp parsing failed"))?;
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
    std::mem::forget(namespaces);
    Ok(())
}
