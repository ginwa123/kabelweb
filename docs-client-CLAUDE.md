# custom_http_client — conventions

This module is **independent** of `modules/http/HttpClient.zig`.
Do not modify `HttpClient.zig` from this module's scope.

When asked to migrate HTTP-call code from `HttpClient.zig` to this
module, that's a separate work item. Update `root.zig` re-exports
in `src/root.zig` only after at least one consumer is migrated.
