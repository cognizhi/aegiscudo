import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const schemasDir = path.join(process.cwd(), "schemas");
const fixturesDir = path.join(schemasDir, "fixtures");
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

const schemaFiles = (await readdir(schemasDir)).filter((file) => file.endsWith(".schema.json"));
const schemas = new Map();

for (const file of schemaFiles) {
  const schema = JSON.parse(await readFile(path.join(schemasDir, file), "utf8"));
  schemas.set(file.replace(".schema.json", ""), schema);
  ajv.addSchema(schema, schema.$id);
}

const fixtureFiles = (await readdir(fixturesDir)).filter((file) => file.endsWith(".json"));
let failures = 0;

for (const file of fixtureFiles) {
  const schemaName = file.split(".")[0];
  const schema = schemas.get(schemaName);
  const shouldBeInvalid = file.includes(".invalid.");
  if (!schema) {
    console.error(`No schema found for fixture ${file}`);
    failures += 1;
    continue;
  }
  const validate = ajv.getSchema(schema.$id);
  const fixture = JSON.parse(await readFile(path.join(fixturesDir, file), "utf8"));
  const isValid = Boolean(validate?.(fixture));
  if (shouldBeInvalid ? isValid : !isValid) {
    console.error(`Schema validation failed for ${file}`);
    console.error(validate?.errors);
    failures += 1;
  }
}

if (failures > 0) {
  process.exit(1);
}

console.log(`Validated ${fixtureFiles.length} schema fixtures.`);