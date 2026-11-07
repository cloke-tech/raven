// ClokeOS: installed Windows programs in the application menu.
// `raven --install-menu [Applications folder]` reads the shortcuts (.lnk) the installers left in the Start Menu folders of the prefix
// and writes one Name.app bundle per program: a start script, an Info.plist and the program's icon as PNG. CloakServer lists bundles
// of ~/Applications. A bundle that this tool wrote carries the key RavenShortcut and is rewritten or removed with its shortcut;
// bundles of other origin are never touched.
#pragma once

#include "nt/prefix.h"
#include "pe/pe.h"
#include "pe/resources.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace raven::menu {

namespace fs = std::filesystem;

struct Shortcut {
	std::string name;       // file name without .lnk
	std::string target;     // Windows path of the program
	std::string arguments;
	std::string directory;  // working directory (Windows path)
	std::string icon;       // Windows path of the file holding the icon
};

inline std::string utf8_of(const std::u16string &text)
{
	std::string out;
	for (size_t i = 0; i < text.size(); ++i) {
		uint32_t c = text[i];
		if (c >= 0xd800 && c < 0xdc00 && i + 1 < text.size() && text[i + 1] >= 0xdc00 && text[i + 1] < 0xe000)
			c = 0x10000 + ((c - 0xd800) << 10) + (text[++i] - 0xdc00);
		if (c < 0x80) out += char(c);
		else if (c < 0x800) { out += char(0xc0 | c >> 6); out += char(0x80 | (c & 63)); }
		else if (c < 0x10000) { out += char(0xe0 | c >> 12); out += char(0x80 | ((c >> 6) & 63)); out += char(0x80 | (c & 63)); }
		else { out += char(0xf0 | c >> 18); out += char(0x80 | ((c >> 12) & 63)); out += char(0x80 | ((c >> 6) & 63)); out += char(0x80 | (c & 63)); }
	}
	return out;
}

inline uint32_t le(const std::vector<uint8_t> &b, size_t at, size_t n)
{
	uint32_t v = 0;
	for (size_t i = 0; i < n && at + i < b.size(); ++i) v |= uint32_t(b[at + i]) << (8 * i);
	return v;
}

inline std::vector<uint8_t> read_file(const fs::path &path)
{
	std::ifstream in(path, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

// [MS-SHLLINK]: header, optional item id list, link info (local base path), then the string data.
inline std::optional<Shortcut> parse_link(const fs::path &path)
{
	const auto b = read_file(path);
	if (b.size() < 76 || le(b, 0, 4) != 0x4c) return std::nullopt;
	const uint32_t flags = le(b, 20, 4);
	size_t at = 76;
	if (flags & 0x1) at += 2 + le(b, at, 2);
	Shortcut link;
	link.name = path.stem().string();
	if (flags & 0x2) {
		const size_t start = at, size = le(b, at, 4), header = le(b, at + 4, 4), kind = le(b, at + 8, 4);
		if (size < 28 || start + size > b.size()) return std::nullopt;
		if (kind & 1) {
			size_t offset = le(b, start + 16, 4);
			if (header >= 0x24 && le(b, start + 28, 4)) {
				std::u16string wide;
				for (size_t p = start + le(b, start + 28, 4); p + 1 < b.size() && (b[p] || b[p + 1]); p += 2) wide.push_back(char16_t(b[p] | b[p + 1] << 8));
				link.target = utf8_of(wide);
			} else {
				for (size_t p = start + offset; p < b.size() && b[p]; ++p) link.target.push_back(char(b[p]));
			}
		}
		at = start + size;
	}
	const auto text = [&](uint32_t flag) -> std::string {
		if (!(flags & flag)) return {};
		const size_t count = le(b, at, 2);
		at += 2;
		std::string out;
		if (flags & 0x80) {
			std::u16string wide;
			for (size_t i = 0; i < count && at + 2 * i + 1 < b.size(); ++i) wide.push_back(char16_t(b[at + 2 * i] | b[at + 2 * i + 1] << 8));
			out = utf8_of(wide);
			at += count * 2;
		} else {
			out.assign(reinterpret_cast<const char *>(b.data()) + std::min(at, b.size()), std::min(count, b.size() - std::min(at, b.size())));
			at += count;
		}
		return out;
	};
	text(0x4);                            // name
	const auto relative = text(0x8);
	link.directory = text(0x10);
	link.arguments = text(0x20);
	link.icon = text(0x40);
	if (link.target.empty()) link.target = relative;
	if (link.target.empty()) return std::nullopt;
	return link;
}

// ---- icon: the biggest image of the first icon group of an .exe or .ico, as PNG -----------------------------------------

inline uint32_t crc32_of(const uint8_t *data, size_t n, uint32_t crc = 0)
{
	static uint32_t table[256];
	if (!table[1])
		for (uint32_t i = 0; i < 256; ++i) {
			uint32_t c = i;
			for (int k = 0; k < 8; ++k) c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
			table[i] = c;
		}
	crc = ~crc;
	for (size_t i = 0; i < n; ++i) crc = table[(crc ^ data[i]) & 255] ^ (crc >> 8);
	return ~crc;
}

// RGBA to PNG with stored (uncompressed) deflate blocks: big, but valid and no library needed.
inline std::vector<uint8_t> png_of(const std::vector<uint8_t> &rgba, uint32_t width, uint32_t height)
{
	std::vector<uint8_t> raw;
	for (uint32_t y = 0; y < height; ++y) {
		raw.push_back(0);
		raw.insert(raw.end(), rgba.begin() + size_t(y) * width * 4, rgba.begin() + size_t(y + 1) * width * 4);
	}
	std::vector<uint8_t> z{0x78, 0x01};
	uint32_t a = 1, s = 0;
	for (const auto byte : raw) { a = (a + byte) % 65521; s = (s + a) % 65521; }
	for (size_t at = 0; at < raw.size();) {
		const size_t n = std::min<size_t>(65535, raw.size() - at);
		z.push_back(at + n == raw.size() ? 1 : 0);
		z.push_back(uint8_t(n)); z.push_back(uint8_t(n >> 8)); z.push_back(uint8_t(~n)); z.push_back(uint8_t(~n >> 8));
		z.insert(z.end(), raw.begin() + at, raw.begin() + at + n);
		at += n;
	}
	const uint32_t adler = s << 16 | a;
	for (int shift = 24; shift >= 0; shift -= 8) z.push_back(uint8_t(adler >> shift));
	std::vector<uint8_t> png{0x89, 'P', 'N', 'G', 13, 10, 26, 10};
	const auto chunk = [&](const char *type, const std::vector<uint8_t> &data) {
		for (int shift = 24; shift >= 0; shift -= 8) png.push_back(uint8_t(data.size() >> shift));
		std::vector<uint8_t> body(type, type + 4);
		body.insert(body.end(), data.begin(), data.end());
		png.insert(png.end(), body.begin(), body.end());
		const uint32_t crc = crc32_of(body.data(), body.size());
		for (int shift = 24; shift >= 0; shift -= 8) png.push_back(uint8_t(crc >> shift));
	};
	std::vector<uint8_t> header;
	for (const uint32_t v : {width, height}) for (int shift = 24; shift >= 0; shift -= 8) header.push_back(uint8_t(v >> shift));
	header.insert(header.end(), {8, 6, 0, 0, 0});
	chunk("IHDR", header);
	chunk("IDAT", z);
	chunk("IEND", {});
	return png;
}

// One icon image (PNG, or the DIB of an .ico/RT_ICON without file header) to PNG bytes.
inline std::vector<uint8_t> icon_png(const std::vector<uint8_t> &d)
{
	if (d.size() > 8 && d[0] == 0x89 && d[1] == 'P') return d;
	if (d.size() < 40 || le(d, 0, 4) < 40) return {};
	const uint32_t header = le(d, 0, 4), width = le(d, 4, 4), height2 = le(d, 8, 4), bits = le(d, 14, 2), used = le(d, 32, 4);
	const uint32_t height = height2 / 2;
	if (!width || width > 512 || !height || height > 512) return {};
	const size_t colors = bits <= 8 ? (used ? used : size_t(1) << bits) : 0;
	const size_t table = header, pixels = table + colors * 4;
	const size_t stride = ((size_t(width) * bits + 31) / 32) * 4, mask_stride = ((size_t(width) + 31) / 32) * 4;
	const size_t masks = pixels + stride * height;
	std::vector<uint8_t> rgba(size_t(width) * height * 4);
	bool any_alpha = false;
	for (uint32_t y = 0; y < height; ++y)
		for (uint32_t x = 0; x < width; ++x) {
			const size_t row = pixels + size_t(height - 1 - y) * stride;
			uint8_t r = 0, g = 0, bl = 0, a = 255;
			if (bits == 32) {
				const size_t p = row + x * 4;
				if (p + 3 >= d.size()) return {};
				bl = d[p]; g = d[p + 1]; r = d[p + 2]; a = d[p + 3];
				any_alpha = any_alpha || a;
			} else if (bits == 24) {
				const size_t p = row + x * 3;
				if (p + 2 >= d.size()) return {};
				bl = d[p]; g = d[p + 1]; r = d[p + 2];
			} else if (bits == 8 || bits == 4 || bits == 1) {
				const size_t p = row + (size_t(x) * bits) / 8;
				if (p >= d.size()) return {};
				const unsigned shift = 8 - bits - (unsigned(x) * bits) % 8;
				const size_t index = (d[p] >> shift) & ((1u << bits) - 1);
				const size_t c = table + index * 4;
				if (c + 2 >= d.size()) return {};
				bl = d[c]; g = d[c + 1]; r = d[c + 2];
			} else {
				return {};
			}
			uint8_t *out = &rgba[(size_t(y) * width + x) * 4];
			out[0] = r; out[1] = g; out[2] = bl; out[3] = a;
		}
	if (bits != 32 || !any_alpha)
		for (uint32_t y = 0; y < height; ++y)
			for (uint32_t x = 0; x < width; ++x) {
				const size_t p = masks + size_t(height - 1 - y) * mask_stride + x / 8;
				rgba[(size_t(y) * width + x) * 4 + 3] = p < d.size() && (d[p] >> (7 - x % 8) & 1) ? 0 : 255;
			}
	return png_of(rgba, width, height);
}

inline std::vector<uint8_t> best_icon(const std::vector<uint8_t> &file, bool is_ico)
{
	std::vector<std::pair<uint32_t, std::vector<uint8_t>>> images;   // size, image data
	if (is_ico) {
		if (file.size() < 6) return {};
		for (size_t i = 0, n = le(file, 4, 2); i < n && 6 + i * 16 + 16 <= file.size(); ++i) {
			const size_t e = 6 + i * 16;
			const uint32_t size = le(file, e + 8, 4), offset = le(file, e + 12, 4), w = file[e] ? file[e] : 256;
			if (offset + size <= file.size()) images.push_back({w, std::vector<uint8_t>(file.begin() + offset, file.begin() + offset + size)});
		}
	} else {
		try {
			PEImage image(file);
			const auto resources = image.resources();
			const auto offset_of = [&](uint32_t rva) -> std::optional<size_t> {
				for (const auto &s : image.sections)
					if (rva >= s.address && rva < s.address + std::max(s.virtual_size, s.file_size)) return size_t(rva - s.address) + s.file_offset;
				return std::nullopt;
			};
			const auto bytes_of = [&](const PEResource &r) -> std::vector<uint8_t> {
				const auto o = offset_of(r.data_address);
				if (!o || *o + r.size > file.size()) return {};
				return std::vector<uint8_t>(file.begin() + *o, file.begin() + *o + r.size);
			};
			const PEResource *group = nullptr;
			for (const auto &r : resources)
				if (const auto *t = std::get_if<uint32_t>(&r.type); t && *t == 14 && !group) group = &r;
			if (!group) return {};
			const auto g = bytes_of(*group);
			for (size_t i = 0, n = le(g, 4, 2); i < n && 6 + i * 14 + 14 <= g.size(); ++i) {
				const size_t e = 6 + i * 14;
				const uint32_t w = g[e] ? g[e] : 256, id = le(g, e + 12, 2);
				for (const auto &r : resources)
					if (const auto *t = std::get_if<uint32_t>(&r.type), *n2 = std::get_if<uint32_t>(&r.name); t && *t == 3 && n2 && *n2 == id) {
						images.push_back({w, bytes_of(r)});
						break;
					}
			}
		} catch (...) {
			return {};
		}
	}
	std::sort(images.begin(), images.end(), [](const auto &a, const auto &b) { return a.first > b.first; });
	for (const auto &[size, data] : images)
		if (const auto png = icon_png(data); !png.empty()) return png;
	return {};
}

// ---- bundles -----------------------------------------------------------------------------------------------------------

inline std::string xml_escape(const std::string &s)
{
	std::string out;
	for (const char c : s) out += c == '&' ? "&amp;" : c == '<' ? "&lt;" : c == '>' ? "&gt;" : std::string(1, c);
	return out;
}

inline std::string sh_quote(const std::string &s)
{
	std::string out = "'";
	for (const char c : s) out += c == '\'' ? "'\\''" : std::string(1, c);
	return out + "'";
}

inline void collect(const fs::path &folder, std::vector<fs::path> &links)
{
	std::error_code ec;
	if (!fs::is_directory(folder, ec)) return;
	for (fs::recursive_directory_iterator it(folder, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; it.increment(ec))
		if (it->is_regular_file(ec) && it->path().extension() == ".lnk") links.push_back(it->path());
}

inline std::string lower(std::string s)
{
	for (auto &c : s) c = char(std::tolower((unsigned char)c));
	return s;
}

// Returns how many bundles were written.
inline int install(const NativePrefix &prefix, const fs::path &applications)
{
	std::vector<fs::path> links;
	const fs::path root = prefix.c_drive();
	collect(root / "ProgramData/Microsoft/Windows/Start Menu/Programs", links);
	std::error_code ec;
	// Of the users' own Start Menu folders only the user's: the tree is shared, the application menu is not.
	const char *login = std::getenv("USER");
	if (login && *login)
		collect(root / "Users" / login / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs", links);
	std::set<std::string> wanted;
	int written = 0;
	fs::create_directories(applications, ec);
	for (const auto &path : links) {
		const auto link = parse_link(path);
		if (!link) continue;
		const std::string target_lower = lower(link->target), name_lower = lower(link->name);
		if (target_lower.size() < 4 || target_lower.substr(target_lower.size() - 4) != ".exe") continue;
		if (name_lower.find("uninstall") != std::string::npos || name_lower.find("unins") == 0 || target_lower.find("unins0") != std::string::npos) continue;
		const auto host = prefix.resolve(link->target);
		if (!host || !fs::exists(*host, ec)) continue;
		std::string clean;
		for (const char c : link->name) if (c != '/' && c != ':' && c != '\\' && c != '"') clean += c;
		if (clean.empty() || wanted.count(clean)) continue;
		wanted.insert(clean);
		const fs::path bundle = applications / (clean + ".app");
		if (fs::exists(bundle / "Contents/Info.plist", ec)) {
			const auto old = read_file(bundle / "Contents/Info.plist");
			if (std::string(old.begin(), old.end()).find("RavenShortcut") == std::string::npos) continue;   // not ours
		} else if (fs::exists(bundle, ec)) {
			continue;
		}
		fs::create_directories(bundle / "Contents/MacOS", ec);
		fs::create_directories(bundle / "Contents/Resources", ec);
		std::string identifier = "org.raven.";
		for (const char c : lower(clean)) identifier += std::isalnum((unsigned char)c) ? c : '-';
		const bool has_icon = [&] {
			std::string source = link->icon.empty() ? link->target : link->icon;
			const auto comma = source.rfind(',');
			if (comma != std::string::npos && source.find_first_not_of("-0123456789", comma + 1) == std::string::npos) source.erase(comma);
			for (const char c : std::string("\"")) source.erase(std::remove(source.begin(), source.end(), c), source.end());
			auto icon_host = prefix.resolve(source);
			if (!icon_host || !fs::exists(*icon_host, ec)) icon_host = host;
			const bool ico = lower(icon_host->extension().string()) == ".ico";
			auto png = best_icon(read_file(*icon_host), ico);
			if (png.empty() && icon_host != host) png = best_icon(read_file(*host), false);
			if (png.empty()) return false;
			std::ofstream(bundle / "Contents/Resources/icon.png", std::ios::binary).write(reinterpret_cast<const char *>(png.data()), std::streamsize(png.size()));
			return true;
		}();
		std::ofstream plist(bundle / "Contents/Info.plist");
		// The same layout as CloakServer writes its own property lists in: key and value on lines of their own.
		const auto item = [&](const char *key, const std::string &value) { plist << "\t<key>" << key << "</key>\n\t<string>" << xml_escape(value) << "</string>\n"; };
		plist << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			<< "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
			<< "<plist version=\"1.0\">\n<dict>\n";
		item("CFBundleName", clean);
		item("CFBundleDisplayName", clean);
		item("CFBundleIdentifier", identifier);
		item("CFBundleExecutable", "launch");
		if (has_icon) item("CFBundleIconFile", "icon");
		item("CFBundlePackageType", "APPL");
		{
			// The window class Raven gives the program's windows (the stem of the file, no blanks): ties the windows to this app
			std::string window_class = host->stem().string();
			for (auto &c : window_class) if (c == ' ' || c == '\t') c = '_';
			item("CLWindowClasses", window_class);
		}
		item("RavenShortcut", link->target);
		plist << "</dict>\n</plist>\n";
		plist.close();
		const fs::path script = bundle / "Contents/MacOS/launch";
		{
			std::ofstream out(script);
			const std::string directory = link->directory.empty() ? std::string() : prefix.resolve(link->directory).value_or(fs::path()).string();
			out << "#!/bin/sh\n# written by `raven --install-menu` from a Start Menu shortcut\n";
			if (!directory.empty()) out << "cd " << sh_quote(directory) << " 2>/dev/null\n";
			out << "exec raven " << sh_quote(host->string());
			if (!link->arguments.empty()) out << " " << link->arguments;   // the shortcut's arguments are a command line already
			out << "\n";
		}
		::chmod(script.c_str(), 0755);
		++written;
	}
	// A bundle whose shortcut is gone (the program was uninstalled) goes with it.
	for (const auto &entry : fs::directory_iterator(applications, ec)) {
		if (entry.path().extension() != ".app") continue;
		const auto info = read_file(entry.path() / "Contents/Info.plist");
		if (std::string(info.begin(), info.end()).find("RavenShortcut") == std::string::npos) continue;
		if (!wanted.count(entry.path().stem().string())) fs::remove_all(entry.path(), ec);
	}
	return written;
}


// `raven --add-app <program.exe> [Applications folder]`: a program started without a shortcut (a double click on its file) gets an app bundle too,
// so that it shows in the Dock while it runs. Installers, the tools Raven ships and programs that already have a bundle are left out.
inline bool add_app(const NativePrefix &prefix, const fs::path &program, const fs::path &applications)
{
	std::error_code ec;
	const std::string stem = program.stem().string();
	const std::string lowered = lower(stem);
	if (stem.empty() || lowered.find("setup") != std::string::npos || lowered.find("install") != std::string::npos || lowered.find("unins") != std::string::npos ||
		lower(program.extension().string()) != ".exe" || !fs::exists(program, ec))
		return false;
	if (program.string().rfind("/usr/libexec/raven/", 0) == 0)
		return false;
	std::string clean;
	for (const char c : stem) if (c != '/' && c != ':' && c != '\\' && c != '"') clean += c;
	const fs::path bundle = applications / (clean + ".app");
	if (clean.empty() || fs::exists(bundle, ec))
		return false;
	fs::create_directories(bundle / "Contents/MacOS", ec);
	fs::create_directories(bundle / "Contents/Resources", ec);
	const auto png = best_icon(read_file(program), false);
	if (!png.empty())
		std::ofstream(bundle / "Contents/Resources/icon.png", std::ios::binary).write(reinterpret_cast<const char *>(png.data()), std::streamsize(png.size()));
	std::string window_class = stem;
	for (auto &c : window_class) if (c == ' ' || c == '\t') c = '_';
	std::string identifier = "org.raven.";
	for (const char c : lower(clean)) identifier += std::isalnum((unsigned char)c) ? c : '-';
	std::ofstream plist(bundle / "Contents/Info.plist");
	const auto item = [&](const char *key, const std::string &value) { plist << "\t<key>" << key << "</key>\n\t<string>" << xml_escape(value) << "</string>\n"; };
	plist << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		<< "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n";
	item("CFBundleName", clean);
	item("CFBundleDisplayName", clean);
	item("CFBundleIdentifier", identifier);
	item("CFBundleExecutable", "launch");
	if (!png.empty()) item("CFBundleIconFile", "icon");
	item("CFBundlePackageType", "APPL");
	item("CLWindowClasses", window_class);
	item("RavenProgram", program.string());
	plist << "</dict>\n</plist>\n";
	plist.close();
	const fs::path script = bundle / "Contents/MacOS/launch";
	{
		std::ofstream out(script);
		out << "#!/bin/sh\n# written by `raven --add-app` for a program that was started without a shortcut\n";
		out << "cd " << sh_quote(program.parent_path().string()) << " 2>/dev/null\nexec raven " << sh_quote(program.string()) << "\n";
	}
	::chmod(script.c_str(), 0755);
	(void)prefix;
	return true;
}

}
