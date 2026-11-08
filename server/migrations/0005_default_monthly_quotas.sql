-- Set the requested default budget for existing departments and users.
UPDATE departments
SET monthly_limit_cents=80000,
    member_limit_cap_cents=10000;

UPDATE users
SET personal_limit_cents=10000;

UPDATE users
SET display_name='系统管理员'
WHERE role='platform_admin' AND display_name='平台管理员';
