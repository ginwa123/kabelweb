//! One-liner HTTP-verb helpers that build a Request and call perform.
//! These are the "easy to read" call site for callers who don't need
//! per-request overrides beyond headers/body.

const std = @import("std");
const Client = @import("client.zig").Client;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Header = @import("request.zig").Header;
const Method = @import("request.zig").Method;
const Options = @import("options.zig").Options;
const Error = @import("client.zig").Error;

pub fn get(client: *Client, url: []const u8, options: Options) Error!Response {
    return client.perform(.{ .method = .GET, .url = url }, options);
}

pub fn post(
    client: *Client,
    url: []const u8,
    body: []const u8,
    headers: []const Header,
    options: Options,
) Error!Response {
    return client.perform(.{
        .method = .POST,
        .url = url,
        .headers = headers,
        .body = body,
    }, options);
}

pub fn put(
    client: *Client,
    url: []const u8,
    body: []const u8,
    headers: []const Header,
    options: Options,
) Error!Response {
    return client.perform(.{
        .method = .PUT,
        .url = url,
        .headers = headers,
        .body = body,
    }, options);
}

pub fn patch(
    client: *Client,
    url: []const u8,
    body: []const u8,
    headers: []const Header,
    options: Options,
) Error!Response {
    return client.perform(.{
        .method = .PATCH,
        .url = url,
        .headers = headers,
        .body = body,
    }, options);
}

pub fn delete(
    client: *Client,
    url: []const u8,
    headers: []const Header,
    options: Options,
) Error!Response {
    return client.perform(.{
        .method = .DELETE,
        .url = url,
        .headers = headers,
    }, options);
}
