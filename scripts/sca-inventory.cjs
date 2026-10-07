function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function pythonName(name) {
  if (typeof name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) {
    throw new Error("invalid Python distribution name");
  }
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

function npmInventory(manifest, lock) {
  if (!object(manifest) || !object(lock) || lock.lockfileVersion !== 3 ||
      !object(lock.packages) || !object(lock.packages[""])) {
    throw new Error("invalid npm manifest or lockfile");
  }
  const root = lock.packages[""];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const declared = manifest[field] ?? {};
    const locked = root[field] ?? {};
    if (!object(declared) || !object(locked) ||
        JSON.stringify(Object.entries(declared).sort()) !==
        JSON.stringify(Object.entries(locked).sort())) {
      throw new Error("npm root declarations differ from lockfile");
    }
  }

  const coordinates = new Map();
  for (const [location, entry] of Object.entries(lock.packages)) {
    if (location === "") continue;
    if (!object(entry) || entry.link === true || entry.private === true ||
        !location.startsWith("node_modules/") ||
        location.includes("\\") || location.split("/").includes("..")) {
      throw new Error("unsupported npm package entry");
    }
    const inferred = location.split("node_modules/").at(-1);
    const name = entry.name ?? inferred;
    if (typeof name !== "string" ||
        !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name)) {
      throw new Error("invalid npm package name");
    }
    if (typeof entry.version !== "string" ||
        !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(entry.version)) {
      throw new Error("npm package lacks an exact version");
    }
    if (entry.resolved !== undefined &&
        (typeof entry.resolved !== "string" ||
         !entry.resolved.startsWith("https://registry.npmjs.org/"))) {
      throw new Error("unsupported npm resolution source");
    }
    const key = JSON.stringify([name, entry.version]);
    if (!coordinates.has(key)) {
      coordinates.set(key, {
        ecosystem: "npm", name, version: entry.version, locations: [],
      });
    }
    coordinates.get(key).locations.push(location);
  }
  if (!coordinates.size) throw new Error("empty npm inventory");
  return {
    scope: "all locked npm entries, including optional/platform-specific entries",
    installedStateVerified: false,
    declaredRoots: {
      dependencies: manifest.dependencies ?? {},
      devDependencies: manifest.devDependencies ?? {},
      optionalDependencies: manifest.optionalDependencies ?? {},
    },
    packages: [...coordinates.values()].map((item) => ({
      ...item, locations: item.locations.sort(),
    })).sort((a, b) =>
      a.name.localeCompare(b.name) || a.version.localeCompare(b.version)
    ),
  };
}

function pythonInventory(requirements, distributions) {
  if (typeof requirements !== "string" || !Array.isArray(distributions)) {
    throw new Error("invalid Python inventory input");
  }
  const roots = [];
  for (const raw of requirements.split(/\r?\n/)) {
    const line = raw.split("#", 1)[0].trim();
    if (!line) continue;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(line)) {
      throw new Error("unsupported Python requirement; explicit parser extension needed");
    }
    const name = pythonName(line);
    if (roots.includes(name)) throw new Error("duplicate Python requirement");
    roots.push(name);
  }
  if (!roots.length) throw new Error("empty Python requirements");

  const installed = new Map();
  for (const item of distributions) {
    if (!object(item)) throw new Error("invalid installed distribution");
    const name = pythonName(item.name);
    if (typeof item.version !== "string" || !item.version.trim() ||
        /\s/.test(item.version)) {
      throw new Error("invalid installed Python version");
    }
    if (installed.has(name)) throw new Error("duplicate installed distribution");
    installed.set(name, {
      ecosystem: "PyPI", name, version: item.version,
    });
  }
  for (const name of roots) {
    if (!installed.has(name)) throw new Error("declared Python root not installed");
  }
  return {
    scope: "all installed project-venv distributions, including tooling and extras",
    reproducibleLockfile: false,
    freshResolutionPerformed: false,
    dependencyClosureProven: false,
    declaredRoots: roots.sort().map((name) => installed.get(name)),
    packages: [...installed.values()].sort((a, b) => a.name.localeCompare(b.name)),
  };
}

module.exports = { npmInventory, pythonInventory, pythonName };
