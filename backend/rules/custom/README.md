# Custom YARA rules

Put your own `.yar` / `.yara` files here. They are compiled together with the
built-in rules in `../builtin/` and run against every uploaded file and its
extracted/unpacked contents.

Optional `meta` fields the UI understands:

- `description` – shown as the rule summary
- `severity` – `low`, `medium` or `high` (defaults to `low`)
- `category` – free text used for grouping

A rule file that fails to compile is skipped and reported in the job's
limitations, so one broken file does not disable the others.
