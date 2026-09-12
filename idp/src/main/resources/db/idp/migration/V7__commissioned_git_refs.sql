-- The Git refs a commissioned credential may push (principal-bound-git-refs-plan.md in the qits
-- superproject, contract C2).
--
-- WHAT IT HOLDS: one ref per line, the same plain form as `claims` (V5). GitRefs owns the format
-- and the rules; ClientRegistry reads it and TokenService puts it in the token as `git_refs`.
--
-- NULL AND THE EMPTY STRING MEAN DIFFERENT THINGS, and postgres keeps them apart. NULL: the
-- commission stated no list, and its tokens carry no `git_refs` claim — exactly as before this
-- column existed. The empty string: the empty list, "may push nothing".
--
-- `text`, not varchar(n): a list may hold 500 entries of up to 255 characters each.
--
-- Nullable with no default, so every existing row reads as "not stated" and no live token changes
-- when this runs.

alter table idp_client add column git_refs text;
