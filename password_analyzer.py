"""
Password Strength Analyzer
--------------------------
Core logic module that evaluates the strength of user-entered passwords.

Key features:
  - Checks password length, complexity, and uniqueness
  - Suggests stronger password alternatives
  - Demonstrates basic cryptography concepts (entropy, hashing)

This module is intentionally dependency-free (pure Python standard library)
so the analysis logic can be reused from the CLI, the web app, or tests.
"""

import hashlib
import hmac
import math
import random
import re
import secrets
import string
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Common / weak password database (a small bundled list)
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "12345", "1234",
    "qwerty", "abc123", "password1", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "master", "login",
    "princess", "football", "shadow", "sunshine", "iloveyou", "trustno1",
    "000000", "987654321", "654321", "qwerty123", "zxcvbn", "passw0rd",
    "password123", "qwertyuiop", "asdfghjkl", "11111111", "222222",
    "p@ssw0rd", "pass", "god", "secret", "hello", "charlie",
}


# ---------------------------------------------------------------------------
# Character sets used for complexity checks / generation
# ---------------------------------------------------------------------------
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~`"

_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "abcdefghijklmnopqrstuvwxyz",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class StrengthResult:
    score: int = 0                       # 0 (weak) .. 100 (strong)
    label: str = "Very Weak"
    entropy: float = 0.0                 # estimated entropy in bits
    crack_time: str = "instant"          # human readable estimate
    checks: List[dict] = field(default_factory=list)  # per-criteria results
    suggestions: List[str] = field(default_factory=list)
    uniqueness: bool = True
    hash_sha256: str = ""
    brute_force: dict = field(default_factory=dict)

    @property
    def strength_label(self) -> str:
        return self.label


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _check_sequences(pw: str) -> bool:
    """Return True if the password contains a dangerous sequence (e.g. 'abc')."""
    lowered = pw.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in lowered:
                return True
    return False


def _check_common(pw: str) -> bool:
    return pw.lower() in COMMON_PASSWORDS


def _repeated_chars(pw: str) -> bool:
    return bool(re.search(r"(.)\1{2,}", pw))


def _char_classes(pw: str) -> int:
    classes = 0
    if any(c in LOWERCASE for c in pw):
        classes += 1
    if any(c in UPPERCASE for c in pw):
        classes += 1
    if any(c in DIGITS for c in pw):
        classes += 1
    if any(c in SYMBOLS for c in pw):
        classes += 1
    return classes


def effective_character_pool(pw: str) -> int:
    """Size of the character pool a random password of this composition
    could draw from -- used to estimate entropy."""
    pool = 0
    if any(c in LOWERCASE for c in pw):
        pool += len(LOWERCASE)
    if any(c in UPPERCASE for c in pw):
        pool += len(UPPERCASE)
    if any(c in DIGITS for c in pw):
        pool += len(DIGITS)
    if any(c in SYMBOLS for c in pw):
        pool += len(SYMBOLS)
    return max(pool or (len(pw) if pw else 1), 1)


def estimate_entropy(pw: str) -> float:
    """Shannon-style estimate of information entropy (in bits).

    For a password of length n drawn from a pool of size N the entropy is
        H = n * log2(N)
    but we penalise non-uniform character distributions using the Shannon
    formula over actual character frequencies. We take the conservative
    (lower) of the two estimates so that predictable passwords score lower.
    """
    if not pw:
        return 0.0

    n = len(pw)
    pool = effective_character_pool(pw)
    uniform = n * math.log2(pool)

    # Empirical Shannon entropy over actual frequencies
    freq = {}
    for ch in pw:
        freq[ch] = freq.get(ch, 0) + 1
    shannon = -sum(
        (c / n) * math.log2(c / n) for c in freq.values()
    ) * n

    entropy = max(min(uniform, shannon), 0.0)

    # Penalties for known predictable patterns
    if _check_common(pw):
        entropy = min(entropy, 20)
    if _check_sequences(pw):
        entropy *= 0.6
    if _repeated_chars(pw):
        entropy *= 0.7

    return abs(round(max(entropy, 0.0), 1))


def crack_time_estimate(entropy_bits: float) -> str:
    """Rough human-readable guess for online/offline cracking time
    at ~1e9 guesses/sec (offline hash cracking)."""
    if entropy_bits <= 0:
        return "instant"
    guesses = 2 ** entropy_bits
    seconds = guesses / 1_000_000_000

    if seconds < 1:
        return "instant"
    if seconds < 60:
        return "under a minute"
    if seconds < 3600:
        return f"~{int(seconds / 60)} minutes"
    if seconds < 86400:
        return f"~{int(seconds / 3600)} hours"
    if seconds < 86400 * 30:
        return f"~{int(seconds / 86400)} days"
    if seconds < 86400 * 365:
        return f"~{int(seconds / 86400 / 30)} months"
    if seconds < 86400 * 365 * 100:
        return f"~{int(seconds / 86400 / 365)} years"
    return "centuries"


def hash_password(pw: str, salt: Optional[str] = None) -> dict:
    """Demonstrate basic cryptography: return SHA-256 / SHA-512 hashes.

    Note: for *storing* user passwords you should NEVER use raw SHA-*. Use a
    purpose-built password KDF such as bcrypt, scrypt, PBKDF2 or argon2
    (with a random salt and high work factor). SHA is shown here purely to
    illustrate the concept of a one-way hash.

    PBKDF2 with a high iteration count slows each attempt down - this is the
    key defence against offline brute-force attacks once a hash has leaked.
    """
    salt_bytes = (salt or "").encode("utf-8")
    iterations = 600_000  # OWASP-recommended PBKDF2-HMAC-SHA256 iterations
    data = salt_bytes + pw.encode("utf-8")
    pbkdf2 = hashlib.pbkdf2_hmac(
        "sha256", pw.encode("utf-8"), salt_bytes, iterations
    ).hex()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "hmac_sha256": hmac.new(b"static-key-demo", data, hashlib.sha256).hexdigest(),
        "pbkdf2_600k": pbkdf2,
        "salt_used": salt,
        "iterations": iterations,
    }


def analyze_password(
    password: str,
    password_history: Optional[List[str]] = None,
) -> StrengthResult:
    """Analyse a password and return a full StrengthResult object.

    Args:
        password: the candidate password to evaluate.
        password_history: optional list of previously used passwords to
            check uniqueness / reuse.
    """
    result = StrengthResult()
    result.uniqueness = True

    if not password:
        result.score = 0
        result.label = "Very Weak"
        result.suggestions.append("Enter a password to analyse it.")
        return result

    checks = []

    # --- Length ---------------------------------------------------------
    n = len(password)
    length_ok = n >= 12
    if n < 8:
        length_score = 0
        length_msg = f"Too short ({n} chars). Use at least 12 characters."
    elif n < 12:
        length_score = 10
        length_msg = f"Could be longer ({n} chars). Aim for 12+ characters."
    else:
        length_score = 25
        length_msg = f"Good length ({n} characters)."
    checks.append({"name": "Length", "score": length_score, "max": 25,
                   "passed": length_ok, "message": length_msg, "weight": "high"})

    # --- Complexity -----------------------------------------------------
    classes = _char_classes(password)
    has_upper = "UPPERCASE" if any(c in UPPERCASE for c in password) else "no uppercase"
    has_lower = "lowercase" if any(c in LOWERCASE for c in password) else "no lowercase"
    has_digit = "digits" if any(c in DIGITS for c in password) else "no digits"
    has_sym = "symbols" if any(c in SYMBOLS for c in password) else "no symbols"
    complexity = (
        "+1 points for each character type: "
        f"{has_upper}, {has_lower}, {has_digit}, {has_sym} "
        f"(total {classes} types)"
    )
    complexity_score = classes * 10  # 0..40
    checks.append({"name": "Complexity", "score": complexity_score, "max": 40,
                   "passed": classes >= 3, "message": complexity, "weight": "high"})

    # --- Uniqueness / common words --------------------------------------
    unique_score = 25
    unique_msgs = []
    if _check_common(password):
        unique_score -= 25
        unique_msgs.append("Password is on the list of most common passwords!")
    if _check_sequences(password):
        unique_score -= 10
        unique_msgs.append("Contains an easy keyboard/number sequence (e.g. 'abc', '123').")
    if _repeated_chars(password):
        unique_score -= 5
        unique_msgs.append("Contains repeated characters (e.g. 'aaa').")
    if not unique_msgs:
        unique_msgs.append("No known common-password matches found.")
    checks.append({"name": "Uniqueness",
                   "score": max(unique_score, 0), "max": 25,
                   "passed": unique_score >= 20, "message": " ".join(unique_msgs),
                   "weight": "medium"})

    # --- Entropy & crack time -------------------------------------------
    entropy = estimate_entropy(password)
    result.entropy = entropy
    result.crack_time = crack_time_estimate(entropy)

    # --- Password history / reuse (if a history is provided) ------------
    component_score = length_score + complexity_score + unique_score + 10  # +10 baseline
    if password_history:
        reuse = [p for p in password_history if p == password]
        if reuse:
            component_score = 0
            result.uniqueness = False
            checks.append({"name": "Reuse", "score": 0, "max": 10,
                           "passed": False,
                           "message": "This password was used before. Choose a new one.",
                           "weight": "critical"})
        else:
            checks.append({"name": "Reuse", "score": 10, "max": 10,
                           "passed": True,
                           "message": "This password has not been used previously.",
                           "weight": "critical"})
            component_score += 10

    # Blend the component score with the measured entropy so that a short or
    # predictable password can never be rated strong just because it happens
    # to tick the right boxes.
    # Entropy mapping:
    #   0 bits  -> factor 0 (penalise hard)
    #   60+ bits-> factor 1 (full component score)
    entropy_factor = min(entropy / 60.0, 1.0)
    score = round(component_score * (0.4 + 0.6 * entropy_factor))

    score = max(0, min(score, 100))

    # --- Label ----------------------------------------------------------
    if score >= 80:
        label = "Very Strong"
    elif score >= 60:
        label = "Strong"
    elif score >= 40:
        label = "Moderate"
    elif score >= 20:
        label = "Weak"
    else:
        label = "Very Weak"

    result.score = score
    result.label = label
    result.checks = checks
    result.hash_sha256 = hash_password(password)["sha256"]
    result.brute_force = brute_force_resistance(entropy)

    # --- Suggestions ----------------------------------------------------
    result.suggestions = build_suggestions(password, checks, classes, n)

    return result


# ---------------------------------------------------------------------------
# Suggestions
# ---------------------------------------------------------------------------
def build_suggestions(password: str, checks, classes: int, n: int) -> List[str]:
    suggestions = []
    if n < 12:
        suggestions.append("Make the password at least 12 characters long.")
    if classes < 4:
        missing = []
        if not any(c in UPPERCASE for c in password):
            missing.append("uppercase letters")
        if not any(c in DIGITS for c in password):
            missing.append("numbers")
        if not any(c in SYMBOLS for c in password):
            missing.append("symbols")
        if missing:
            suggestions.append("Add " + ", ".join(missing) + " to improve complexity.")
    if _check_common(password):
        suggestions.append("Avoid using extremely common passwords - they are cracked first.")
    if _check_sequences(password):
        suggestions.append("Don't use predictable sequences like 'abc', '123', or 'qwerty'.")
    if _repeated_chars(password):
        suggestions.append("Avoid repeating the same character multiple times in a row.")
    if not suggestions:
        suggestions.append("Great password! Consider using a passphrase of several random words for extra strength.")
    return suggestions[:5]


_WORD_LIST = [
    "abacus", "acetic", "acorn", "adobe", "agate", "airway", "albino", "alpine",
    "amber", "anchor", "apricot", "arcade", "atlas", "aurora", "avocado", "badger",
    "bamboo", "banana", "battery", "beanie", "beacon", "bistro", "blizzard", "boulder",
    "breeze", "brindle", "bronze", "bubble", "buffalo", "butter", "cabinet", "cactus",
    "caliber", "camper", "canary", "candle", "canyon", "castle", "cedar", "chamber",
    "chisel", "chrome", "cinder", "citrus", "clover", "cobalt", "comet", "copper",
    "coral", "coyote", "crystal", "curtain", "cyclone", "dahlia", "dagger", "dawn",
    "dolphin", "drift", "drizzle", "eagle", "ember", "falcon", "feather", "fjord",
    "flamingo", "forest", "fossil", "foxglove", "galaxy", "geyser", "glacier",
    "granite", "harbor", "heron", "horizon", "hunter", "iceberg", "island", "jackal",
    "jaguar", "kayak", "lantern", "lavender", "leopard", "lighthouse", "lily", "lunar",
    "magnet", "maple", "marble", "meadow", "meteor", "monsoon", "moose", "mountain",
    "nebula", "nimbus", "novel", "ocean", "olive", "orbit", "orchid", "otter",
    "panda", "papaya", "pebble", "pelican", "phoenix", "pinecone", "plasma", "polar",
    "prism", "quartz", "radish", "raven", "reef", "rhubarb", "river", "saffron",
    "salamander", "sandwich", "saturn", "scallop", "shark", "silver", "skylark",
    "snapdragon", "snowdrop", "solar", "sparrow", "spring", "starfish", "sugarloaf",
    "summit", "sunset", "swan", "tangerine", "thunder", "topaz", "toucan", "tundra",
    "turkey", "turtle", "umbrella", "valley", "violet", "walrus", "willow", "wisteria",
    "zephyr", "zircon", "acacia", "advent", "albatross", "amber", "anvil", "aster",
    "attic", "aurora", "axon", "barley", "bayous", "beacon", "beetle", "birch",
    "bison", "blackbird", "blossom", "bluebell", "boomerang", "bramble", "brook",
    "buffalo", "burrow", "butterfly", "cabaret", "cabbage", "cacao", "calibre",
    "camellia", "candlewood", "caper", "cardinal", "cartwheel", "cavern", "celsius",
    "chamois", "charter", "chickadee", "chinquapin", "chowder", "cicada", "cinder",
    "climber", "cloverleaf", "cohort", "comet", "compass", "conifer", "copperhead",
    "cornflower", "cottonwood", "coyote", "cranberry", "crescent", "cricket", "cypress",
    "dangle", "damselfly", "dandelion", "davenport", "daybreak", "deer", "delphinium",
    "denim", "dinosaur", "dolphin", "dove", "dragon", "drake", "drumlin", "duck",
    "eagle", "echelon", "edelweiss", "egret", "eider", "elk", "elm", "emerald",
    "emu", "evergreen", "farfalle", "falcon", "ferret", "fig", "fir", "firefly",
    "flamingo", "flax", "foghorn", "fox", "frog", "frost", "gazelle", "gecko",
    "gerbil", "gibbon", "giraffe", "glacier", "goat", "goldfinch", "gopher", "gorilla",
    "grackle", "granite", "greyhound", "grouse", "gull", "guppy", "harbor", "hare",
    "hawk", "hazel", "heather", "hermit", "heron", "hickory", "honey", "hornet",
    "horse", "hound", "hummingbird", "ibis", "impala", "indigo", "iris", "ironwood",
    "ivory", "ivy", "jackdaw", "jackrabbit", "jay", "jellyfish", "juniper", "kaolin",
    "kelp", "kestrel", "kingfisher", "kiwi", "koala", "kudu", "laburnum", "ladybug",
    "lagoon", "lamb", "larch", "lark", "lavender", "leech", "lemur", "liger",
    "lilac", "limestone", "lion", "lobster", "loon", "luna", "lynx", "mackerel",
    "magnolia", "mallard", "mango", "manta", "maple", "marmot", "marsh", "marten",
    "marzipan", "meadowlark", "mimosa", "mink", "minnow", "mole", "mongoose", "moose",
    "morning", "moss", "moth", "mountain", "mule", "mushroom", "mustang", "myrtle",
    "narcissus", "nettle", "nightingale", "nodding", "nuthatch", "oak", "ocean",
    "otter", "owl", "oyster", "palm", "panda", "pangolin", "pansy", "panther",
    "parrot", "pelican", "penguin", "peony", "perch", "periwinkle", "pheasant",
    "pigeon", "pine", "pintail", "piranha", "platypus", "plover", "polar", "pony",
    "poppy", "porcupine", "porpoise", "pronghorn", "puffin", "puma", "quail", "quarry",
    "quetzal", "quokka", "raccoon", "ram", "raven", "redwood", "reindeer", "rhino",
    "robin", "rooster", "rose", "saffron", "sage", "salamander", "salmon", "sandpiper",
    "sapphire", "scarlet", "seaplane", "serpent", "shark", "sheep", "shrike", "shrimp",
    "silverfish", "skink", "skunk", "sloth", "snail", "snake", "snowdrop", "sole",
    "sparrow", "spider", "squid", "squash", "squirrel", "starling", "stork", "sturgeon",
    "sunflower", "swallow", "swan", "swift", "sycamore", "tapir", "tarantula", "teak",
    "termite", "tern", "thrush", "tiger", "toad", "tomato", "trout", "tulip",
    "turkey", "turtle", "unicorn", "vulture", "walnut", "warbler", "weasel", "whale",
    "willet", "wolf", "wombat", "woodruff", "wren", "yak", "yellowhammer", "zebra",
]


def suggest_strong_password(length: int = 20, with_symbols: bool = True) -> str:
    """Generate a cryptographically strong random password.

    Guarantees at least one of each character class and uses secrets (CSPRNG),
    giving a search space of roughly pool^length which is infeasible to brute
    force. pool = 26 + 26 + 10 + ~30 symbols = ~92, so a 20-char password has
    ~130 bits of entropy.
    """
    length = max(12, min(length, 64))
    pool = LOWERCASE + UPPERCASE + DIGITS + (SYMBOLS if with_symbols else "")

    # Guarantee at least one char from each class for complexity
    classes = [LOWERCASE, UPPERCASE, DIGITS] + ([SYMBOLS] if with_symbols else [])
    password = [secrets.choice(chars) for chars in classes]

    # Fill from unused characters so short generated passwords do not get an
    # unusually low empirical entropy estimate from accidental repeats.
    remaining = length - len(password)
    available = "".join(char for char in pool if char not in password)
    password.extend(secrets.SystemRandom().sample(available, remaining))

    # Shuffle so the guaranteed class chars aren't in predictable positions
    return "".join(secrets.SystemRandom().sample(password, len(password)))


def suggest_passphrase(num_words: int = 5, capitalize: bool = True, separator: str = "-") -> str:
    """Generate a memorable passphrase using a Diceware-style word list.

    With a word list of N words, a k-word passphrase has N^k possible
    combinations. Our list has ~300 words, so a 5-word passphrase has
    roughly 5 * log2(300) ~ 41 bits of entropy. Add a random number/token
    suffix for extra brute-force resistance.
    """
    num_words = max(3, min(num_words, 8))
    chosen = [secrets.choice(_WORD_LIST) for _ in range(num_words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    suffix = str(secrets.randbelow(999))
    return separator.join(chosen) + suffix


def brute_force_resistance(entropy_bits: float) -> dict:
    """Estimate time-to-crack at different attacker speeds.

    Returns a dict of {scenario: time_string} for offline (10^9 and 10^12
    guesses/sec) and online (~10^3 guesses/sec) attacks, plus a verdict that
    indicates whether the password holds up under brute force.
    """
    result = {"scenarios": {}, "recommended": False}
    for name, gps in (
        ("Online attack (10^3 guesses/sec)", 1_000),
        ("Fast offline: 1 billion guesses/sec", 1_000_000_000),
        ("GPU cluster: 1 trillion guesses/sec", 1_000_000_000_000),
    ):
        guesses = 2 ** entropy_bits
        seconds = guesses / gps
        result["scenarios"][name] = crack_time_estimate_for_seconds(seconds)

    # NIST recommends >= 40 bits for basic protection, >= 60 for high value
    result["recommended"] = entropy_bits >= 60
    result["minimum_recommended_bits"] = 60
    return result


def crack_time_estimate_for_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instant"
    if seconds < 60:
        return f"~{int(seconds)} seconds"
    if seconds < 3600:
        return f"~{int(seconds / 60)} minutes"
    if seconds < 86400:
        return f"~{int(seconds / 3600)} hours"
    if seconds < 86400 * 30:
        return f"~{int(seconds / 86400)} days"
    if seconds < 86400 * 365:
        return f"~{int(seconds / 86400 / 30)} months"
    if seconds < 86400 * 365 * 100:
        return f"~{int(seconds / 86400 / 365)} years"
    return "centuries"


if __name__ == "__main__":
    import sys
    demo = sys.argv[1] if len(sys.argv) > 1 else "CorrectHorseBatteryStaple"
    res = analyze_password(demo)
    print(f"Password:        {demo}")
    print(f"Strength:        {res.label} ({res.score}/100)")
    print(f"Entropy:         {res.entropy} bits")
    print(f"Est. crack time: {res.crack_time}")
    print("Checks:")
    for c in res.checks:
        print(f"  - [{c['name']}] {'PASS' if c['passed'] else 'FAIL'} ({c['score']}/{c['max']}) {c['message']}")
    print("Suggestions:")
    for s in res.suggestions:
        print(f"  - {s}")
