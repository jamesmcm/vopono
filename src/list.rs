use super::netns::Lockfile;
use super::util::config_dir;
use std::collections::HashMap;
use std::fs::File;
use walkdir::WalkDir;

pub fn output_list() -> anyhow::Result<()> {
    let namespaces = get_lock_namespaces()?;

    let mut keys = namespaces.keys().into_iter().collect::<Vec<&String>>();
    keys.sort();

    for ns in keys {
        let first_lock = &namespaces.get(ns).as_ref().unwrap()[0];
        println!(
            "{}\t{}\t{}",
            ns, first_lock.ns.provider, first_lock.ns.protocol
        );
        for lock in namespaces.get(ns).unwrap() {
            println!("{}\t{}", &lock.command, &lock.start);
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
                .or_insert(Vec::new())
                .push(lock);
            Ok(())
        })?;
    Ok(namespaces)
}
