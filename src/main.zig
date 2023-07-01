const std = @import("std");

const fs = std.fs;
const random = std.crypto.random;
const mem = std.mem;

const assert = std.debug.assert;

const ArrayList = std.ArrayList;
const Allocator = mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256 = std.crypto.core.aes.Aes256;
const Endian = std.builtin.Endian;

const aes256_block_size = 16;
const aes256_block_number = 8;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    var zlap = try @import("zlap").Zlap.init(allocator, @embedFile("./command.json"));
    defer zlap.deinit();

    if (zlap.is_help) {
        std.debug.print("{s}\n", .{zlap.help_msg});
        return;
    }

    if (zlap.isSubcmdActive("encrypt")) {
        const subcmd = zlap.subcommands.get("encrypt").?;
        return encryptFile(
            subcmd.args.items[0].value.string,
            subcmd.args.items[1].value.string,
            subcmd.args.items[2].value.string,
        );
    } else if (zlap.isSubcmdActive("decrypt")) {
        const subcmd = zlap.subcommands.get("decrypt").?;
        return decryptFile(
            subcmd.args.items[0].value.string,
            subcmd.args.items[1].value.string,
            subcmd.args.items[2].value.string,
        );
    }
}

fn encryptFile(key: []const u8, to_encrypt: []const u8, encrypted: []const u8) !void {
    comptime assert(Sha256.digest_length == 32);

    var key_hasher = Sha256.init(.{});
    key_hasher.update(key);
    const orig_key = key_hasher.finalResult();

    const keys: struct { key: [32]u8, key_rand: [32]u8 } = make_key: {
        var key_rand_orig = [_]u8{0} ** 32;
        random.bytes(&key_rand_orig);
        var key_rand: @Vector(32, u8) = key_rand_orig;
        key_rand ^= @as(@Vector(32, u8), orig_key);
        break :make_key .{ .key = key_rand, .key_rand = key_rand_orig };
    };

    var cipher = Aes256.initEnc(keys.key);
    const plaintext = try fs.cwd().openFile(to_encrypt, .{});
    defer plaintext.close();
    const cipertext = try fs.cwd().createFile(encrypted, .{});
    defer cipertext.close();

    var file_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var aes_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var padding_bytes: u128 = 0;
    while (true) {
        var bytes_read = try plaintext.read(&file_buffer);
        const end_of_encrypt = bytes_read < aes256_block_size * aes256_block_number;
        if (end_of_encrypt) {
            padding_bytes = (aes256_block_size * aes256_block_number) - bytes_read;
            random.bytes(file_buffer[bytes_read..]);
        }

        cipher.encryptWide(aes256_block_number, &aes_buffer, &file_buffer);
        _ = try cipertext.write(&aes_buffer);

        if (end_of_encrypt) {
            break;
        }
    }
    _ = try cipertext.write(&keys.key_rand);

    var padding_bytes_buf: [@sizeOf(u128)]u8 = undefined;
    var padding_aes_buf: [@sizeOf(u128)]u8 = undefined;
    mem.writeInt(u128, &padding_bytes_buf, padding_bytes, Endian.Big);
    cipher.encrypt(&padding_aes_buf, &padding_bytes_buf);
    _ = try cipertext.write(&padding_aes_buf);
}

fn decryptFile(key: []const u8, input: []const u8, output: []const u8) !void {
    comptime assert(Sha256.digest_length == 32);

    var key_hasher = Sha256.init(.{});
    key_hasher.update(key);
    const orig_key = key_hasher.finalResult();

    const cipertext = try fs.cwd().openFile(input, .{});
    defer cipertext.close();
    const keys: struct { key: [32]u8, key_rand: [32]u8 } = extract_key: {
        var key_buf: [32]u8 = undefined;
        try cipertext.seekFromEnd(-32 - @sizeOf(u128));
        const bytes_read = try cipertext.read(&key_buf);
        assert(bytes_read == 32);
        try cipertext.seekTo(0);

        var key_rand: @Vector(32, u8) = key_buf;
        key_rand ^= @as(@Vector(32, u8), orig_key);
        break :extract_key .{ .key = key_rand, .key_rand = key_buf };
    };

    var cipher = Aes256.initDec(keys.key);
    const padding_bytes = extract_padding: {
        var padding_bytes_buf: [@sizeOf(u128)]u8 = undefined;
        var padding_aes_buf: [@sizeOf(u128)]u8 = undefined;

        try cipertext.seekFromEnd(-@sizeOf(u128));
        const bytes_read = try cipertext.read(&padding_bytes_buf);
        assert(bytes_read == @sizeOf(u128));
        try cipertext.seekTo(0);

        cipher.decrypt(&padding_aes_buf, &padding_bytes_buf);
        break :extract_padding mem.nativeToBig(u128, mem.bytesToValue(u128, &padding_aes_buf));
    };

    const plaintext = try fs.cwd().createFile(output, .{});
    defer plaintext.close();

    var file_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var aes_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var i: u128 = 0;
    while (true) {
        const bytes_read = try cipertext.read(&file_buffer);
        const end_of_decrypt = bytes_read < aes256_block_size * aes256_block_number;
        if (end_of_decrypt) {
            break;
        }

        cipher.decryptWide(aes256_block_number, &aes_buffer, &file_buffer);
        _ = try plaintext.write(&aes_buffer);
        i += 1;
    }

    const to_drop_bytes: u64 = @intCast(i * 128 -| padding_bytes);
    try plaintext.setEndPos(to_drop_bytes);
}
