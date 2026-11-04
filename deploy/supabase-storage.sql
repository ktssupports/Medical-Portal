-- Run in the Supabase SQL editor once. This bucket must remain private.
INSERT INTO storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
VALUES('medical-reports','medical-reports',false,5242880,ARRAY['application/pdf'])
ON CONFLICT(id) DO UPDATE SET public=false,file_size_limit=5242880,allowed_mime_types=ARRAY['application/pdf'];
-- Do not add public SELECT policies to storage.objects.
-- The backend's server-only service-role key accesses files after portal authorization.
