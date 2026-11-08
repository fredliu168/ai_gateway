-- Give the seeded platform administrator an explicit department and monthly
-- personal quota so Playground checks still use the normal quota controls.
UPDATE users
SET department_id='dept-platform', personal_limit_cents=1000000
WHERE id='user-admin' AND role='platform_admin' AND department_id IS NULL;
