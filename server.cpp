/****************************************************************************
 *  SMART BANKING SYSTEM - C++ REST Backend  (MSYS2 UCRT64 / Windows)
 *  ------------------------------------------------------------------
 *  Build : g++ -std=c++17 -O2 -pthread server.cpp -o bank.exe -lsqlite3 -lws2_32
 *  Run   : ./bank.exe --seed      (first run only: creates demo data)
 *          ./bank.exe             (normal runs)
 *  URL   : http://localhost:8080
 *  Logins: admin/admin123   riya/riya123   arjun/arjun123
 ****************************************************************************/
#include "httplib.h"
#include "json.hpp"
#include <sqlite3.h>
#include <iostream>
#include <string>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cctype>

using json = nlohmann::json;
using httplib::Request;
using httplib::Response;

/* ============================ SHA-256 (demo-grade) ============================ */
namespace sha256 {
inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
inline std::string hash(const std::string& data) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::string msg = data;
    uint64_t bitLen = (uint64_t)msg.size() * 8;
    msg.push_back((char)0x80);
    while (msg.size() % 64 != 56) msg.push_back((char)0x00);
    for (int i = 7; i >= 0; --i) msg.push_back((char)((bitLen >> (i * 8)) & 0xFF));
    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)(uint8_t)msg[off+i*4]   << 24) | ((uint32_t)(uint8_t)msg[off+i*4+1] << 16) |
                   ((uint32_t)(uint8_t)msg[off+i*4+2] <<  8) |  (uint32_t)(uint8_t)msg[off+i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1  = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch  = (e & f) ^ (~e & g);
            uint32_t t1  = hh + S1 + ch + K[i] + w[i];
            uint32_t S0  = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2  = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    std::ostringstream os;
    for (int i = 0; i < 8; ++i) os << std::hex << std::setw(8) << std::setfill('0') << h[i];
    return os.str();
}
} // namespace sha256

/* ============================ Globals ============================ */
sqlite3* db = nullptr;
struct Session { int user_id; std::string username; std::string role; };
std::map<std::string, Session> sessions;      // token -> session (in-memory)
std::mutex sessionsMutex;

const double SAVINGS_RATE        = 3.5;       // % p.a.
const double SAVINGS_MIN_BALANCE = 500.0;     // Rs.
const double FD_PREMATURE_RATE   = 1.0;       // % p.a. penalty rate
double fdRateFor(int months) {                // FD tiered rates
    if (months < 6)  return 5.50;
    if (months < 12) return 6.25;
    if (months < 24) return 7.00;
    return 7.50;
}

/* ============================ Small helpers ============================ */
std::string esc(const std::string& s) {       // basic SQL string escaping
    std::string o; o.reserve(s.size());
    for (char c : s) { if (c == '\'') o += "''"; else o += c; }
    return o;
}
double round2(double v) { return std::round(v * 100.0) / 100.0; }
std::string money(double v) {
    std::ostringstream os; os << std::fixed << std::setprecision(2) << v; return os.str();
}
std::string genToken() {
    static std::mt19937 rng((unsigned)time(nullptr) ^ 0x9e3779b9);
    std::uniform_int_distribution<int> d(0, 15); std::ostringstream os;
    for (int i = 0; i < 40; ++i) os << std::hex << d(rng);
    return os.str();
}
std::string genAccountNumber() {
    static std::mt19937 rng((unsigned)time(nullptr) ^ 0x1234abcd);
    std::uniform_int_distribution<int> d(0, 9); std::ostringstream os;
    os << "SBS"; for (int i = 0; i < 10; ++i) os << d(rng);
    return os.str();
}
static std::mutex timeMutex;
std::string nowStr() {
    std::lock_guard<std::mutex> lk(timeMutex);
    time_t t = time(nullptr); tm lt = *localtime(&t);
    char buf[32]; strftime(buf, 32, "%Y-%m-%d %H:%M:%S", &lt); return buf;
}
std::string addMonths(int months) {
    std::lock_guard<std::mutex> lk(timeMutex);
    time_t t = time(nullptr); tm lt = *localtime(&t);
    lt.tm_mon += months; mktime(&lt);                 // normalizes overflow
    char buf[32]; strftime(buf, 32, "%Y-%m-%d %H:%M:%S", &lt); return buf;
}

/* ============================ DB helpers ============================ */
json runQuery(const std::string& sql) {
    json rows = json::array();
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        std::cerr << "[SQL ERR] " << sqlite3_errmsg(db) << " | " << sql << "\n"; return rows;
    }
    int n = sqlite3_column_count(st);
    while (sqlite3_step(st) == SQLITE_ROW) {
        json row = json::object();
        for (int i = 0; i < n; ++i) {
            const char* name = sqlite3_column_name(st, i);
            switch (sqlite3_column_type(st, i)) {
                case SQLITE_INTEGER: row[name] = (long long)sqlite3_column_int64(st, i); break;
                case SQLITE_FLOAT:   row[name] = sqlite3_column_double(st, i);           break;
                case SQLITE_NULL:    row[name] = nullptr;                                 break;
                default:             row[name] = std::string((const char*)sqlite3_column_text(st, i));
            }
        }
        rows.push_back(row);
    }
    sqlite3_finalize(st); return rows;
}
bool runExec(const std::string& sql) {
    char* err = nullptr;
    bool ok = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK;
    if (err) { if (!ok) std::cerr << "[SQL ERR] " << err << "\n"; sqlite3_free(err); }
    return ok;
}
bool begin()    { return runExec("BEGIN IMMEDIATE"); }
bool commit()   { return runExec("COMMIT"); }
bool rollback() { return runExec("ROLLBACK"); }

void recordTxn(long long accId, const std::string& type, double amount, double balAfter,
               const std::string& desc, const std::string& related) {
    runExec("INSERT INTO transactions (account_id,txn_type,amount,balance_after,description,related_account) VALUES ("
        + std::to_string(accId) + ",'" + type + "'," + money(amount) + "," + money(balAfter) +
        ",'" + esc(desc) + "','" + esc(related) + "')");
}

/* ============================ JSON / auth helpers ============================ */
std::string jstr(const json& j, const char* k) {
    if (j.contains(k) && j[k].is_string()) return j[k].get<std::string>(); return "";
}
long long jll(const json& j, const char* k, long long dflt = -1) {
    if (!j.contains(k)) return dflt;
    const json& v = j[k];
    if (v.is_number_integer() || v.is_number_unsigned()) return v.get<long long>();
    if (v.is_number_float()) return (long long)v.get<double>();
    return dflt;
}
bool getAmount(const json& j, double& out) {
    if (!j.contains("amount") || !j["amount"].is_number()) return false;
    double a = j["amount"].get<double>();
    if (!std::isfinite(a) || a <= 0 || a > 10000000) return false;
    out = round2(a); return true;
}
bool validUsername(const std::string& u) {
    if (u.size() < 3 || u.size() > 20) return false;
    for (char c : u) if (!std::isalnum((unsigned char)c) && c != '_') return false;
    return true;
}
void sendJson(Response& res, const json& j, int status = 200) {
    res.status = status; res.set_content(j.dump(), "application/json");
}
void sendError(Response& res, const std::string& msg, int status = 400) {
    sendJson(res, json{{"error", msg}}, status);
}
bool authSession(const Request& req, Session& out) {
    std::string h = req.get_header_value("Authorization");
    if (h.rfind("Bearer ", 0) != 0) return false;
    std::lock_guard<std::mutex> lk(sessionsMutex);
    auto it = sessions.find(h.substr(7));
    if (it == sessions.end()) return false;
    out = it->second; return true;
}
bool requireAdmin(const Request& req, Response& res, Session& s) {
    if (!authSession(req, s)) { sendError(res, "Not authenticated", 401);  return false; }
    if (s.role != "admin")    { sendError(res, "Admin access required", 403); return false; }
    return true;
}
json findAccountById(long long id) {
    json r = runQuery("SELECT * FROM accounts WHERE id=" + std::to_string(id));
    return r.empty() ? json(nullptr) : r[0];
}
json findAccountByNumber(const std::string& num) {
    json r = runQuery("SELECT * FROM accounts WHERE account_number='" + esc(num) + "'");
    return r.empty() ? json(nullptr) : r[0];
}
std::string uniqueAccountNumber() {
    for (int i = 0; i < 6; ++i) {
        std::string n = genAccountNumber();
        if (runQuery("SELECT id FROM accounts WHERE account_number='" + n + "'").empty()) return n;
    }
    return genAccountNumber();
}

/* ============================ Database init ============================ */
void initDatabase() {
    runExec("PRAGMA foreign_keys=ON;");
    runExec("CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "password TEXT NOT NULL,"
        "full_name TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'customer',"
        "created_at TEXT DEFAULT (datetime('now','localtime')));");
    runExec("CREATE TABLE IF NOT EXISTS accounts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id INTEGER NOT NULL,"
        "account_number TEXT UNIQUE NOT NULL,"
        "account_type TEXT NOT NULL,"                 // savings | current | fixed_deposit
        "balance REAL NOT NULL DEFAULT 0,"
        "interest_rate REAL NOT NULL DEFAULT 0,"
        "status TEXT NOT NULL DEFAULT 'active',"      // active | frozen | closed
        "created_at TEXT DEFAULT (datetime('now','localtime')),"
        "FOREIGN KEY(user_id) REFERENCES users(id));");
    runExec("CREATE TABLE IF NOT EXISTS transactions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "account_id INTEGER NOT NULL,"
        "txn_type TEXT NOT NULL,"                     // deposit|withdrawal|transfer_in|transfer_out|fd_open|fd_maturity|fd_premature
        "amount REAL NOT NULL,"
        "balance_after REAL NOT NULL,"
        "description TEXT DEFAULT '',"
        "related_account TEXT DEFAULT '',"
        "created_at TEXT DEFAULT (datetime('now','localtime')),"
        "FOREIGN KEY(account_id) REFERENCES accounts(id));");
    runExec("CREATE TABLE IF NOT EXISTS fixed_deposits ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id INTEGER NOT NULL,"
        "account_id INTEGER NOT NULL,"
        "source_account_id INTEGER NOT NULL,"
        "principal REAL NOT NULL,"
        "rate REAL NOT NULL,"
        "tenure_months INTEGER NOT NULL,"
        "maturity_date TEXT NOT NULL,"
        "status TEXT NOT NULL DEFAULT 'active',"
        "payout REAL,"
        "closed_at TEXT,"
        "created_at TEXT DEFAULT (datetime('now','localtime')));");
    if (runQuery("SELECT id FROM users WHERE username='admin'").empty()) {
        runExec("INSERT INTO users (username,password,full_name,role) VALUES ('admin','"
                + sha256::hash("admin123") + "','Bank Administrator','admin')");
        std::cout << "[SEED] Default admin created -> admin / admin123\n";
    }
}

/* ============================ Demo data seeding ============================ */
void seedDemo() {
    if (!runQuery("SELECT id FROM users WHERE username='riya'").empty()) {
        std::cout << "[SEED] Demo data already present.\n"; return;
    }
    auto insUser = [&](const std::string& u, const std::string& p, const std::string& name, const std::string& ago) {
        runExec("INSERT INTO users (username,password,full_name,role,created_at) VALUES ('" + u +
                "','" + sha256::hash(p) + "','" + name + "','customer', datetime('now','localtime','" + ago + "'))");
        return sqlite3_last_insert_rowid(db);
    };
    long long riya  = insUser("riya",  "riya123",  "Riya Sharma",  "-30 days");
    long long arjun = insUser("arjun", "arjun123", "Arjun Mehta", "-400 days");
    auto insAcc = [&](long long uid, const std::string& num, const std::string& type,
                      double bal, double rate, const std::string& ago) {
        runExec("INSERT INTO accounts (user_id,account_number,account_type,balance,interest_rate,created_at) VALUES ("
                + std::to_string(uid) + ",'" + num + "','" + type + "'," + money(bal) + "," + money(rate) +
                ", datetime('now','localtime','" + ago + "'))");
        return sqlite3_last_insert_rowid(db);
    };
    long long a1 = insAcc(riya,  "SBS1000000001", "savings",       48500, 3.5, "-30 days");
    long long a2 = insAcc(riya,  "SBS1000000002", "current",       12800, 0,   "-25 days");
    long long a3 = insAcc(arjun, "SBS1000000003", "savings",       36750, 3.5, "-400 days");
    long long a4 = insAcc(arjun, "SBS1000000004", "current",        8500, 0,   "-20 days");
    long long a5 = insAcc(riya,  "SBS1000000005", "fixed_deposit", 50000, 7.0, "-5 days");
    long long a6 = insAcc(arjun, "SBS1000000006", "fixed_deposit", 30000, 7.0, "-390 days");
    auto tx = [&](long long acc, const std::string& type, double amt, double after,
                  const std::string& desc, const std::string& rel, const std::string& ago) {
        runExec("INSERT INTO transactions (account_id,txn_type,amount,balance_after,description,related_account,created_at) VALUES ("
                + std::to_string(acc) + ",'" + type + "'," + money(amt) + "," + money(after) + ",'" + esc(desc) +
                "','" + rel + "', datetime('now','localtime','" + ago + "'))");
    };
    tx(a1,"deposit",60000,60000,"Account opened with initial deposit","","-30 days");
    tx(a1,"withdrawal",5000,55000,"ATM withdrawal","","-25 days");
    tx(a1,"transfer_out",50000,5000,"FD opened (12 months @ 7.0% p.a.)","SBS1000000005","-20 days");
    tx(a1,"deposit",55000,60000,"Salary credit","","-15 days");
    tx(a1,"transfer_in",3500,63500,"Received from SBS1000000003","SBS1000000003","-10 days");
    tx(a1,"withdrawal",10000,53500,"UPI payment to merchant","","-7 days");
    tx(a1,"withdrawal",10000,43500,"UPI payment to merchant","","-5 days");
    tx(a1,"deposit",5000,48500,"Refund credited","","-3 days");
    tx(a2,"deposit",15000,15000,"Account opened with initial deposit","","-25 days");
    tx(a2,"withdrawal",3000,12000,"Vendor payment","","-12 days");
    tx(a2,"deposit",800,12800,"Cash deposit","","-2 days");
    tx(a3,"deposit",45000,45000,"Account opened with initial deposit","","-400 days");
    tx(a3,"transfer_out",30000,15000,"FD opened (12 months @ 7.0% p.a.)","SBS1000000006","-390 days");
    tx(a3,"deposit",30000,45000,"Salary credit","","-28 days");
    tx(a3,"withdrawal",6000,39000,"ATM withdrawal","","-22 days");
    tx(a3,"transfer_out",3500,35500,"Rent share","SBS1000000001","-10 days");
    tx(a3,"deposit",1250,36750,"Refund credited","","-4 days");
    tx(a4,"deposit",12000,12000,"Account opened with initial deposit","","-20 days");
    tx(a4,"withdrawal",3100,8900,"Office supplies","","-8 days");
    tx(a4,"withdrawal",400,8500,"Fuel","","-1 days");
    tx(a5,"fd_open",50000,50000,"FD created from SBS1000000001","SBS1000000001","-5 days");
    tx(a6,"fd_open",30000,30000,"FD created from SBS1000000003","SBS1000000003","-390 days");
    runExec("INSERT INTO fixed_deposits (user_id,account_id,source_account_id,principal,rate,tenure_months,maturity_date,created_at) VALUES ("
        + std::to_string(riya) + "," + std::to_string(a5) + "," + std::to_string(a1) +
        ",50000,7.0,12, datetime('now','localtime','-5 days','+12 months'), datetime('now','localtime','-5 days'))");
    runExec("INSERT INTO fixed_deposits (user_id,account_id,source_account_id,principal,rate,tenure_months,maturity_date,created_at) VALUES ("
        + std::to_string(arjun) + "," + std::to_string(a6) + "," + std::to_string(a3) +
        ",30000,7.0,12, datetime('now','localtime','-390 days','+12 months'), datetime('now','localtime','-390 days'))");
    std::cout << "[SEED] Demo customers -> riya/riya123 (active FD), arjun/arjun123 (matured FD)\n";
}

/* ================================ MAIN ================================ */
int main(int argc, char* argv[]) {
    if (sqlite3_open("bank.db", &db) != SQLITE_OK) {
        std::cerr << "Cannot open bank.db: " << sqlite3_errmsg(db) << "\n"; return 1;
    }
    initDatabase();
    if (argc > 1 && std::string(argv[1]) == "--seed") seedDemo();

    httplib::Server svr;
    svr.set_default_headers({{"Access-Control-Allow-Origin", "*"},
                             {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
                             {"Access-Control-Allow-Headers", "Content-Type, Authorization"}});
    svr.Options(R"(/api/.*)", [](const Request&, Response& res) { res.status = 204; });
    svr.set_exception_handler([](const Request&, Response& res, std::exception_ptr ep) {
        try { std::rethrow_exception(ep); }
        catch (const std::exception& e) { sendJson(res, json{{"error", e.what()}}, 500); }
        catch (...) { sendJson(res, json{{"error", "Internal server error"}}, 500); }
    });

    /* ------------------------------ AUTH: LOGIN ------------------------------ */
    svr.Post("/api/login", [](const Request& req, Response& res) {
        try {
            json b = json::parse(req.body);
            std::string u = jstr(b, "username"), p = jstr(b, "password");
            if (u.empty() || p.empty()) return sendError(res, "Username and password are required");
            json r = runQuery("SELECT id,username,full_name,role,password FROM users WHERE username='" + esc(u) + "'");
            if (r.empty() || r[0]["password"].get<std::string>() != sha256::hash(p))
                return sendError(res, "Invalid username or password", 401);
            std::string token = genToken();
            {
                std::lock_guard<std::mutex> lk(sessionsMutex);
                sessions[token] = Session{ (int)r[0]["id"].get<long long>(),
                                           r[0]["username"].get<std::string>(),
                                           r[0]["role"].get<std::string>() };
            }
            sendJson(res, json{{"token", token}, {"user_id", r[0]["id"]}, {"username", r[0]["username"]},
                               {"full_name", r[0]["full_name"]}, {"role", r[0]["role"]}});
        } catch (...) { sendError(res, "Invalid request body"); }
    });

    /* ------------------------------ AUTH: SIGNUP ------------------------------ */
    svr.Post("/api/signup", [](const Request& req, Response& res) {
        try {
            json b = json::parse(req.body);
            std::string u = jstr(b, "username"), p = jstr(b, "password"), name = jstr(b, "full_name");
            if (!validUsername(u))     return sendError(res, "Username must be 3-20 chars (letters, numbers, _)");
            if (p.size() < 4)          return sendError(res, "Password must be at least 4 characters");
            if (name.empty() || name.size() > 60) return sendError(res, "Please enter your full name");
            if (!runQuery("SELECT id FROM users WHERE username='" + esc(u) + "'").empty())
                return sendError(res, "Username is already taken", 409);
            runExec("INSERT INTO users (username,password,full_name,role) VALUES ('" + esc(u) + "','" +
                    sha256::hash(p) + "','" + esc(name) + "','customer')");
            long long uid = sqlite3_last_insert_rowid(db);
            std::string token = genToken();
            {
                std::lock_guard<std::mutex> lk(sessionsMutex);
                sessions[token] = Session{ (int)uid, u, "customer" };
            }
            sendJson(res, json{{"token", token}, {"user_id", uid}, {"username", u},
                               {"full_name", name}, {"role", "customer"}}, 201);
        } catch (...) { sendError(res, "Invalid request body"); }
    });

    /* ------------------------------ AUTH: LOGOUT ------------------------------ */
    svr.Post("/api/logout", [](const Request& req, Response& res) {
        std::string h = req.get_header_value("Authorization");
        if (h.rfind("Bearer ", 0) == 0) {
            std::lock_guard<std::mutex> lk(sessionsMutex);
            sessions.erase(h.substr(7));
        }
        sendJson(res, json{{"ok", true}});
    });

    /* ------------------------------ PROFILE + ACCOUNTS + FDs ------------------------------ */
    svr.Get("/api/me", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        json user = runQuery("SELECT id,username,full_name,role,created_at FROM users WHERE id=" + std::to_string(s.user_id));
        if (user.empty()) return sendError(res, "User not found", 404);
        json accounts = runQuery("SELECT id,account_number,account_type,balance,interest_rate,status,created_at "
                                 "FROM accounts WHERE user_id=" + std::to_string(s.user_id) + " ORDER BY id");
        json fds = runQuery(
            "SELECT f.id,f.principal,f.rate,f.tenure_months,f.maturity_date,f.status,f.payout,f.created_at,"
            "a.account_number AS fd_account_number, s.account_number AS source_account_number "
            "FROM fixed_deposits f JOIN accounts a ON a.id=f.account_id JOIN accounts s ON s.id=f.source_account_id "
            "WHERE f.user_id=" + std::to_string(s.user_id) + " ORDER BY f.id DESC");
        for (auto& f : fds) {                                   // enrich with projections
            double principal = f["principal"].get<double>();
            double rate      = f["rate"].get<double>();
            double months    = (double)f["tenure_months"].get<long long>();
            double interest  = round2(principal * rate * months / 12.0 / 100.0);
            f["projected_interest"] = interest;
            f["maturity_value"]     = round2(principal + interest);
            f["is_matured"] = (f["status"] == "active") && (nowStr() >= f["maturity_date"].get<std::string>());
        }
        sendJson(res, json{{"user", user[0]}, {"accounts", accounts}, {"fds", fds}});
    });

    /* ------------------------------ OPEN ACCOUNT (savings / current) ------------------------------ */
    svr.Post("/api/accounts", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        try {
            json b = json::parse(req.body);
            std::string type = jstr(b, "account_type");
            double initial = round2(b.contains("initial_deposit") && b["initial_deposit"].is_number()
                                    ? b["initial_deposit"].get<double>() : 0);
            if (initial < 0 || initial > 10000000) return sendError(res, "Invalid initial deposit amount");
            double rate = 0;
            if (type == "savings") rate = SAVINGS_RATE;
            else if (type != "current") return sendError(res, "Invalid account type (open FDs from the Fixed Deposit section)");
            std::string num = uniqueAccountNumber();
            runExec("INSERT INTO accounts (user_id,account_number,account_type,balance,interest_rate) VALUES (" +
                    std::to_string(s.user_id) + ",'" + num + "','" + type + "'," + money(initial) + "," + money(rate) + ")");
            long long id = sqlite3_last_insert_rowid(db);
            if (initial > 0) recordTxn(id, "deposit", initial, initial, "Account opened with initial deposit", "");
            sendJson(res, json{{"account", findAccountById(id)}}, 201);
        } catch (...) { sendError(res, "Invalid request body"); }
    });

    /* ------------------------------ DEPOSIT ------------------------------ */
    svr.Post("/api/deposit", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        try {
            json b = json::parse(req.body);
            long long id = jll(b, "account_id");
            double amt; if (!getAmount(b, amt))
                return sendError(res, "Enter a valid amount between Rs.1 and Rs.1,00,00,000");
            json acc = findAccountById(id);
            if (acc.is_null() || acc["user_id"].get<long long>() != s.user_id)
                return sendError(res, "Account not found", 404);
            if (acc["status"] != "active")
                return sendError(res, "Account is " + acc["status"].get<std::string>() + ". Contact the bank.");
            if (acc["account_type"] == "fixed_deposit")
                return sendError(res, "Fixed deposits cannot accept direct deposits");
            begin();
            double newBal = round2(acc["balance"].get<double>() + amt);
            runExec("UPDATE accounts SET balance=" + money(newBal) + " WHERE id=" + std::to_string(id));
            recordTxn(id, "deposit", amt, newBal, jstr(b, "note").empty() ? "Cash deposit" : jstr(b, "note"), "");
            commit();
            sendJson(res, json{{"balance", newBal}, {"account_number", acc["account_number"]}});
        } catch (...) { rollback(); sendError(res, "Invalid request body"); }
    });

    /* ------------------------------ WITHDRAW ------------------------------ */
    svr.Post("/api/withdraw", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        try {
            json b = json::parse(req.body);
            long long id = jll(b, "account_id");
            double amt; if (!getAmount(b, amt))
                return sendError(res, "Enter a valid amount between Rs.1 and Rs.1,00,00,000");
            json acc = findAccountById(id);
            if (acc.is_null() || acc["user_id"].get<long long>() != s.user_id)
                return sendError(res, "Account not found", 404);
            if (acc["status"] != "active")
                return sendError(res, "Account is " + acc["status"].get<std::string>() + ". Contact the bank.");
            if (acc["account_type"] == "fixed_deposit")
                return sendError(res, "Fixed deposit funds are locked until maturity");
            double newBal = round2(acc["balance"].get<double>() - amt);
            if (acc["account_type"] == "savings" && newBal < SAVINGS_MIN_BALANCE)
                return sendError(res, "Savings accounts must maintain a minimum balance of Rs.500");
            if (newBal < 0) return sendError(res, "Insufficient funds");
            begin();
            runExec("UPDATE accounts SET balance=" + money(newBal) + " WHERE id=" + std::to_string(id));
            recordTxn(id, "withdrawal", amt, newBal, jstr(b, "note").empty() ? "ATM withdrawal" : jstr(b, "note"), "");
            commit();
            sendJson(res, json{{"balance", newBal}, {"account_number", acc["account_number"]}});
        } catch (...) { rollback(); sendError(res, "Invalid request body"); }
    });

    /* ------------------------------ TRANSFER (own accounts OR other customers) ------------------------------ */
    svr.Post("/api/transfer", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        try {
            json b = json::parse(req.body);
            long long fromId = jll(b, "from_account_id");
            std::string toNum = jstr(b, "to_account_number");
            double amt; if (!getAmount(b, amt))
                return sendError(res, "Enter a valid amount between Rs.1 and Rs.1,00,00,000");
            if (toNum.empty()) return sendError(res, "Enter the destination account number");
            json from = findAccountById(fromId);
            if (from.is_null() || from["user_id"].get<long long>() != s.user_id)
                return sendError(res, "Source account not found", 404);
            if (from["status"] != "active")
                return sendError(res, "Source account is " + from["status"].get<std::string>());
            if (from["account_type"] == "fixed_deposit")
                return sendError(res, "Cannot transfer from a fixed deposit");
            json to = findAccountByNumber(toNum);
            if (to.is_null()) return sendError(res, "Destination account number not found", 404);
            if (to["id"] == from["id"]) return sendError(res, "Cannot transfer to the same account");
            if (to["status"] != "active")
                return sendError(res, "Destination account is " + to["status"].get<std::string>());
            if (to["account_type"] == "fixed_deposit")
                return sendError(res, "Cannot transfer into a fixed deposit account");

            begin();
            json fromF = findAccountById(fromId);                       // fresh balance inside txn
            double newFrom = round2(fromF["balance"].get<double>() - amt);
            if (from["account_type"] == "savings" && newFrom < SAVINGS_MIN_BALANCE) {
                rollback(); return sendError(res, "Savings accounts must maintain a minimum balance of Rs.500");
            }
            if (newFrom < 0) { rollback(); return sendError(res, "Insufficient funds"); }
            double newTo = round2(to["balance"].get<double>() + amt);
            runExec("UPDATE accounts SET balance=" + money(newFrom) + " WHERE id=" + std::to_string(fromId));
            runExec("UPDATE accounts SET balance=" + money(newTo)   + " WHERE id=" + std::to_string((long long)to["id"]));
            std::string note = jstr(b, "note"); if (note.empty()) note = "Transfer";
            recordTxn(fromId, "transfer_out", amt, newFrom, note, toNum);
            recordTxn((long long)to["id"], "transfer_in", amt, newTo, note, from["account_number"].get<std::string>());
            commit();
            json owner = runQuery("SELECT full_name FROM users WHERE id=" + std::to_string((long long)to["user_id"]));
            sendJson(res, json{{"from_balance", newFrom}, {"to_balance", newTo}, {"to_account_number", toNum},
                               {"to_name", owner.empty() ? json(nullptr) : owner[0]["full_name"]}});
        } catch (...) { rollback(); sendError(res, "Invalid request body"); }
    });

    /* ------------------------------ TRANSACTION HISTORY ------------------------------ */
    svr.Get("/api/transactions", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        try {
            std::string filter;
            if (req.has_param("account_id")) {
                long long id = std::stoll(req.get_param_value("account_id"));
                json acc = findAccountById(id);
                if (acc.is_null() || acc["user_id"].get<long long>() != s.user_id)
                    return sendError(res, "Account not found", 403);
                filter = " AND t.account_id=" + std::to_string(id);
            }
            json txns = runQuery(
                "SELECT t.id,t.txn_type,t.amount,t.balance_after,t.description,t.related_account,t.created_at,"
                "a.account_number,a.account_type FROM transactions t JOIN accounts a ON a.id=t.account_id "
                "WHERE a.user_id=" + std::to_string(s.user_id) + filter +
                " ORDER BY t.created_at DESC, t.id DESC LIMIT 200");
            sendJson(res, json{{"transactions", txns}});
        } catch (...) { sendError(res, "Invalid request"); }
    });

    /* ------------------------------ OPEN FIXED DEPOSIT ------------------------------ */
    svr.Post("/api/fd", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        try {
            json b = json::parse(req.body);
            long long srcId = jll(b, "source_account_id");
            double amt; if (!getAmount(b, amt))
                return sendError(res, "Enter a valid amount between Rs.1 and Rs.1,00,00,000");
            if (amt < 1000) return sendError(res, "Minimum fixed deposit amount is Rs.1,000");
            long long months = jll(b, "tenure_months", 0);
            if (months < 3 || months > 60) return sendError(res, "Tenure must be between 3 and 60 months");
            json src = findAccountById(srcId);
            if (src.is_null() || src["user_id"].get<long long>() != s.user_id)
                return sendError(res, "Source account not found", 404);
            if (src["status"] != "active") return sendError(res, "Source account is " + src["status"].get<std::string>());
            if (src["account_type"] == "fixed_deposit")
                return sendError(res, "Cannot fund an FD from another fixed deposit");
            if (src["account_type"] == "savings" &&
                round2(src["balance"].get<double>() - amt) < SAVINGS_MIN_BALANCE)
                return sendError(res, "Savings accounts must maintain a minimum balance of Rs.500");

            double rate = fdRateFor((int)months);
            std::string maturityDate = addMonths((int)months);
            std::string fdNum = uniqueAccountNumber();

            begin();
            double newSrc = round2(src["balance"].get<double>() - amt);
            runExec("UPDATE accounts SET balance=" + money(newSrc) + " WHERE id=" + std::to_string(srcId));
            runExec("INSERT INTO accounts (user_id,account_number,account_type,balance,interest_rate) VALUES (" +
                    std::to_string(s.user_id) + ",'" + fdNum + "','fixed_deposit'," + money(amt) + "," + money(rate) + ")");
            long long fdAccId = sqlite3_last_insert_rowid(db);
            runExec("INSERT INTO fixed_deposits (user_id,account_id,source_account_id,principal,rate,tenure_months,maturity_date) "
                    "VALUES (" + std::to_string(s.user_id) + "," + std::to_string(fdAccId) + "," +
                    std::to_string(srcId) + "," + money(amt) + "," + money(rate) + "," +
                    std::to_string(months) + ",'" + maturityDate + "')");
            recordTxn(srcId, "transfer_out", amt, newSrc,
                      "FD opened (" + std::to_string(months) + " months @ " + money(rate) + "% p.a.)", fdNum);
            recordTxn(fdAccId, "fd_open", amt, amt,
                      "FD created from " + src["account_number"].get<std::string>(),
                      src["account_number"].get<std::string>());
            commit();

            double interest = round2(amt * rate * (double)months / 12.0 / 100.0);
            sendJson(res, json{{"fd_account_number", fdNum}, {"principal", amt}, {"rate", rate},
                               {"tenure_months", months}, {"maturity_date", maturityDate},
                               {"maturity_value", round2(amt + interest)},
                               {"source_balance", newSrc}}, 201);
        } catch (...) { rollback(); sendError(res, "Invalid request body"); }
    });

    /* ------------------------------ CLOSE / REDEEM FIXED DEPOSIT ------------------------------ */
    svr.Post("/api/fd/close", [](const Request& req, Response& res) {
        Session s; if (!authSession(req, s)) return sendError(res, "Not authenticated", 401);
        try {
            json b = json::parse(req.body);
            json fd = runQuery("SELECT * FROM fixed_deposits WHERE id=" + std::to_string(jll(b, "fd_id")) +
                               " AND user_id=" + std::to_string(s.user_id));
            if (fd.empty()) return sendError(res, "Fixed deposit not found", 404);
            fd = fd[0];
            if (fd["status"] != "active") return sendError(res, "This FD is already closed");

            long long srcId = fd["source_account_id"].get<long long>();
            json srcAcc = findAccountById(srcId);
            if (srcAcc.is_null()) return sendError(res, "Payout account no longer exists", 404);

            double principal = fd["principal"].get<double>();
            double rate      = fd["rate"].get<double>();
            double months    = (double)fd["tenure_months"].get<long long>();
            bool matured = nowStr() >= fd["maturity_date"].get<std::string>();

            double appliedRate, payout; std::string txType, label;
            if (matured) {
                appliedRate = rate;
                payout = round2(principal + principal * rate * months / 12.0 / 100.0);
                txType = "fd_maturity"; label = "FD matured - full payout";
            } else {
                appliedRate = FD_PREMATURE_RATE;
                payout = round2(principal + principal * FD_PREMATURE_RATE * months / 12.0 / 100.0);
                txType = "fd_premature"; label = "FD premature closure (penalty rate 1.0% p.a.)";
            }

            begin();
            double newSrc = round2(srcAcc["balance"].get<double>() + payout);
            runExec("UPDATE accounts SET balance=" + money(newSrc) + " WHERE id=" + std::to_string(srcId));
            runExec("UPDATE accounts SET balance=0, status='closed' WHERE id=" +
                    std::to_string(fd["account_id"].get<long long>()));
            runExec("UPDATE fixed_deposits SET status='closed', payout=" + money(payout) +
                    ", closed_at=datetime('now','localtime') WHERE id=" + std::to_string(fd["id"].get<long long>()));
            recordTxn(srcId, "transfer_in", payout, newSrc, label, fd["account_number"].get<std::string>());
            recordTxn(fd["account_id"].get<long long>(), txType, payout, 0, label,
                      srcAcc["account_number"].get<std::string>());
            commit();
            sendJson(res, json{{"payout", payout}, {"matured", matured}, {"applied_rate", appliedRate},
                               {"credited_to", srcAcc["account_number"]}, {"new_balance", newSrc}});
        } catch (...) { rollback(); sendError(res, "Invalid request body"); }
    });

    /* ================================ ADMIN APIs ================================ */

    svr.Get("/api/admin/summary", [](const Request& req, Response& res) {
        Session s; if (!requireAdmin(req, res, s)) return;
        json totals = runQuery("SELECT COUNT(*) AS account_count, COALESCE(SUM(balance),0) AS total_deposits "
                               "FROM accounts WHERE status!='closed'");
        json byType = runQuery("SELECT account_type, COUNT(*) AS count, COALESCE(SUM(balance),0) AS total "
                               "FROM accounts WHERE status!='closed' GROUP BY account_type");
        json byTxn  = runQuery("SELECT txn_type, COUNT(*) AS count, COALESCE(SUM(amount),0) AS volume "
                               "FROM transactions GROUP BY txn_type");
        json daily  = runQuery("SELECT date(created_at) AS day, COUNT(*) AS count, COALESCE(SUM(amount),0) AS volume "
                               "FROM transactions WHERE created_at >= datetime('now','localtime','-7 days') "
                               "GROUP BY date(created_at) ORDER BY day");
        json users  = runQuery("SELECT COUNT(*) AS customer_count FROM users WHERE role='customer'");
        json today  = runQuery("SELECT COUNT(*) AS count, COALESCE(SUM(amount),0) AS volume FROM transactions "
                               "WHERE date(created_at)=date('now','localtime')");
        sendJson(res, json{{"totals", totals[0]}, {"by_type", byType}, {"by_txn_type", byTxn},
                           {"daily", daily}, {"customers", users[0]}, {"today", today[0]}});
    });

    svr.Get("/api/admin/accounts", [](const Request& req, Response& res) {
        Session s; if (!requireAdmin(req, res, s)) return;
        json rows = runQuery(
            "SELECT a.id,a.account_number,a.account_type,a.balance,a.interest_rate,a.status,a.created_at,"
            "u.id AS user_id,u.username,u.full_name "
            "FROM accounts a JOIN users u ON u.id=a.user_id ORDER BY u.username, a.id");
        sendJson(res, json{{"accounts", rows}});
    });

    svr.Get("/api/admin/transactions", [](const Request& req, Response& res) {
        Session s; if (!requireAdmin(req, res, s)) return;
        std::string limit = "50";
        if (req.has_param("limit")) {
            std::string v = req.get_param_value("limit");
            if (v.size() <= 3 && !v.empty() && v.find_first_not_of("0123456789") == std::string::npos) limit = v;
        }
        json rows = runQuery(
            "SELECT t.id,t.txn_type,t.amount,t.balance_after,t.description,t.related_account,t.created_at,"
            "a.account_number,u.username,u.full_name "
            "FROM transactions t JOIN accounts a ON a.id=t.account_id JOIN users u ON u.id=a.user_id "
            "ORDER BY t.created_at DESC, t.id DESC LIMIT " + limit);
        sendJson(res, json{{"transactions", rows}});
    });

    svr.Post("/api/admin/freeze", [](const Request& req, Response& res) {
        Session s; if (!requireAdmin(req, res, s)) return;
        try {
            json b = json::parse(req.body);
            json acc = findAccountById(jll(b, "account_id"));
            if (acc.is_null()) return sendError(res, "Account not found", 404);
            if (acc["account_type"] == "fixed_deposit")
                return sendError(res, "Fixed deposits are managed through maturity/premature closure");
            std::string newStatus = (acc["status"] == "active") ? "frozen" : "active";
            runExec("UPDATE accounts SET status='" + newStatus + "' WHERE id=" +
                    std::to_string(acc["id"].get<long long>()));
            sendJson(res, json{{"account_id", acc["id"]}, {"account_number", acc["account_number"]},
                               {"status", newStatus}});
        } catch (...) { sendError(res, "Invalid request body"); }
    });

    /* --------------------- SERVE FRONTEND + START SERVER --------------------- */
    svr.set_logger([](const Request& req, const Response& res) {
        std::cout << "  " << req.method << " " << req.path << "  ->  " << res.status << "\n";
    });
    if (!svr.set_mount_point("/", "./public"))
        std::cerr << "[WARN] ./public folder not found - web pages will not be served\n";

    std::cout << "\n  ================================================\n"
              << "   SMART BANKING SYSTEM - C++ backend running\n"
              << "   URL   : http://localhost:8080\n"
              << "   Admin : admin / admin123\n"
              << "  ================================================\n\n";

        int port = 8080;                                   // local default
    if (const char* p = std::getenv("PORT")) {         // cloud sets PORT
        int v = std::atoi(p);
        if (v > 0) port = v;
    }
    if (!svr.listen("0.0.0.0", port)) {
        std::cerr << "[FATAL] Could not bind port " << port << "\n";
    }
    sqlite3_close(db);
    return 0;
}