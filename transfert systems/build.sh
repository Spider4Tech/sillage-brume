#!/usr/bin/env bash
#
# SILLAGE Transfer — construction du binaire.
#
#   ./build.sh              construit puis lance l'autotest
#   ./build.sh --no-test    construit seulement
#   ./build.sh --clean      efface le cache .deps puis reconstruit
#   ./build.sh --package    construit et crée une archive source autonome
#
# Dépendances système : cc, c++ (ou g++), ar, tar, curl (ou wget), git,
# OpenSSL, X11. raylib 6.2 et libdatachannel 0.24.6 sont téléchargés et
# compilés dans .deps au premier build.
#
# SILLAGE est cherché dans sillage/c puis ../sillage/c, ou $SILLAGE_DIR.
# Le binaire est portable par défaut (sans -march=native) ; NATIVE=1 active
# les optimisations spécifiques à la machine de compilation.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CC="${CC:-cc}"
RAYLIB_VERSION="${RAYLIB_VERSION:-6.2}"
DEPS="$ROOT/.deps"
SILLAGE_OBJ="$DEPS/sillage"

# Archive source : dossier SILLAGE local (créé par --package), sinon dépôt.
if [ -z "${SILLAGE_DIR:-}" ]; then
    if [ -f "$ROOT/sillage/c/sillage.h" ]; then
        SILLAGE_DIR="$ROOT/sillage/c"
    else
        SILLAGE_DIR="$ROOT/../sillage/c"
    fi
fi
SILLAGE_LIB="$SILLAGE_OBJ/libsillage.a"
OUT="$ROOT/sillage-transfer"

RUN_TEST=1
CLEAN=0
PACKAGE=0
for arg in "$@"; do
    case "$arg" in
        --no-test) RUN_TEST=0 ;;
        --clean)   CLEAN=1 ;;
        --package) PACKAGE=1 ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Option inconnue : $arg" >&2
            exit 2
            ;;
    esac
done

if [ "$CLEAN" = 1 ]; then
    rm -rf "$DEPS" "$OUT"
fi

mkdir -p "$DEPS" "$SILLAGE_OBJ"

# --------------------------------------------------------------------------
# Vérifications
# --------------------------------------------------------------------------
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "Erreur : compilateur « $CC » introuvable." >&2
    exit 1
fi
if ! command -v ar >/dev/null 2>&1; then
    echo "Erreur : « ar » introuvable (paquet binutils)." >&2
    exit 1
fi
if [ ! -f "$ROOT/sillage_transfer.c" ]; then
    echo "Erreur : sillage_transfer.c introuvable dans $ROOT." >&2
    exit 1
fi
if [ ! -f "$SILLAGE_DIR/sillage.h" ]; then
    echo "Erreur : sources SILLAGE introuvables dans $SILLAGE_DIR." >&2
    echo "         Définissez SILLAGE_DIR=/chemin/vers/sillage/c." >&2
    exit 1
fi
if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists openssl 2>/dev/null; then
    if [ ! -f /usr/include/openssl/evp.h ]; then
        echo "Erreur : en-têtes OpenSSL absents (libssl-dev ou openssl-devel)." >&2
        exit 1
    fi
fi

# --------------------------------------------------------------------------
# raylib (binaire statique officiel, mis en cache)
# --------------------------------------------------------------------------
case "$(uname -m)" in
    x86_64|amd64) RAY_ARCH=amd64 ;;
    aarch64|arm64) RAY_ARCH=arm64 ;;
    *) RAY_ARCH="" ;;
esac

RAYLIB_DIR="${RAYLIB_DIR:-$DEPS/raylib-${RAYLIB_VERSION}_linux_${RAY_ARCH}}"
if [ ! -f "$RAYLIB_DIR/include/raylib.h" ] || [ ! -f "$RAYLIB_DIR/lib/libraylib.a" ]; then
    if [ -z "$RAY_ARCH" ]; then
        echo "Erreur : architecture non prise en charge ($(uname -m))." >&2
        echo "         Fournissez RAYLIB_DIR=/chemin/vers/raylib." >&2
        exit 1
    fi
    URL="https://github.com/raysan5/raylib/releases/download/${RAYLIB_VERSION}/raylib-${RAYLIB_VERSION}_linux_${RAY_ARCH}.tar.gz"
    ARCHIVE="$DEPS/raylib-${RAYLIB_VERSION}_linux_${RAY_ARCH}.tar.gz"
    echo "→ Téléchargement de raylib ${RAYLIB_VERSION}…"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --connect-timeout 20 -o "$ARCHIVE" "$URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$ARCHIVE" "$URL"
    else
        echo "Erreur : curl ou wget requis pour télécharger raylib." >&2
        exit 1
    fi
    tar -xzf "$ARCHIVE" -C "$DEPS"
    rm -f "$ARCHIVE"
    if [ ! -f "$RAYLIB_DIR/lib/libraylib.a" ]; then
        # Le nom du dossier peut varier selon la distribution.
        found="$(find "$DEPS" -maxdepth 2 -name libraylib.a -print -quit)"
        if [ -z "$found" ]; then
            echo "Erreur : libraylib.a introuvable après extraction." >&2
            exit 1
        fi
        RAYLIB_DIR="$(dirname "$(dirname "$found")")"
    fi
fi

# --------------------------------------------------------------------------
# libdatachannel (WebRTC/ICE/STUN/DataChannel, statique, sans média)
# --------------------------------------------------------------------------
LDC_VERSION="${LIBDATACHANNEL_VERSION:-0.24.6}"
LDC_DIR="${LIBDATACHANNEL_DIR:-$DEPS/libdatachannel}"
LDC_BUILD="$LDC_DIR/build"

# PeerJS Cloud utilise une signalisation WebSocket : le client WS de
# libdatachannel doit être compilé. Une ancienne archive .deps construite
# avec NO_WEBSOCKET=ON est automatiquement reconstruite.
if [ -f "$LDC_BUILD/CMakeCache.txt" ] && \
   grep -q 'NO_WEBSOCKET:BOOL=ON' "$LDC_BUILD/CMakeCache.txt"; then
    echo "→ Activation du client WebSocket dans libdatachannel…"
    rm -rf "$LDC_BUILD"
fi

if [ ! -f "$LDC_BUILD/libdatachannel.a" ]; then
    if [ ! -f "$LDC_DIR/CMakeLists.txt" ]; then
        if ! command -v git >/dev/null 2>&1; then
            echo "Erreur : git requis pour télécharger libdatachannel." >&2
            exit 1
        fi
        echo "→ Téléchargement de libdatachannel ${LDC_VERSION}…"
        rm -rf "$LDC_DIR"
        git clone -q --depth 1 --branch "v${LDC_VERSION}" \
            --recurse-submodules --shallow-submodules \
            https://github.com/paullouisageneau/libdatachannel.git "$LDC_DIR"
    fi

    CMAKE_BIN="${CMAKE:-}"
    if [ -z "$CMAKE_BIN" ]; then
        if command -v cmake >/dev/null 2>&1; then
            CMAKE_BIN="$(command -v cmake)"
        elif [ -x "$DEPS/venv/bin/cmake" ]; then
            CMAKE_BIN="$DEPS/venv/bin/cmake"
        else
            echo "→ Installation locale de CMake dans .deps/venv…"
            python3 -m venv "$DEPS/venv"
            "$DEPS/venv/bin/pip" -q install --upgrade pip cmake
            CMAKE_BIN="$DEPS/venv/bin/cmake"
        fi
    fi

    echo "→ Configuration de libdatachannel…"
    "$CMAKE_BIN" -S "$LDC_DIR" -B "$LDC_BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DNO_MEDIA=ON -DNO_WEBSOCKET=OFF -DNO_EXAMPLES=ON -DNO_TESTS=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
    echo "→ Compilation de libdatachannel…"
    "$CMAKE_BIN" --build "$LDC_BUILD" -j"$(nproc)" >/dev/null
fi

LDC_INC="$LDC_DIR/include"
LDC_LIBS=(
    "$LDC_BUILD/libdatachannel.a"
    "$LDC_BUILD/deps/libjuice/libjuice.a"
    "$LDC_BUILD/deps/usrsctp/usrsctplib/libusrsctp.a"
)
for lib in "${LDC_LIBS[@]}"; do
    if [ ! -f "$lib" ]; then
        echo "Erreur : bibliothèque manquante après compilation : $lib" >&2
        exit 1
    fi
done

# --------------------------------------------------------------------------
# SILLAGE : compilation locale en archive statique
# (évite toute incompatibilité ABI avec un libsillage.so préexistant)
# --------------------------------------------------------------------------
SILLAGE_SRCS=(commun.c brume512.c brume512_avx2.c kem.c sig.c isd.c)
SILLAGE_HDRS=(sillage.h brume512_tables.h brume512_simd.h)

# Optimisations SILLAGE. Par défaut : -mavx2 si le CPU de compilation le
# supporte (BRUME exige AVX2 ou NEON pour rester constant-time). Sur un x86
# sans AVX2, on accepte explicitement le repli non constant-time.
NATIVE="${NATIVE:-0}"
ARCH_FLAGS=""
SILLAGE_DEFS=""
case "$(uname -m)" in
    x86_64|amd64)
        if [ "$NATIVE" = 1 ]; then
            ARCH_FLAGS="-march=native"
        elif grep -qw avx2 /proc/cpuinfo 2>/dev/null; then
            ARCH_FLAGS="-mavx2"
        else
            echo "Attention : CPU sans AVX2, repli SILLAGE non constant-time." >&2
            SILLAGE_DEFS="-DSL_REPLI_NON_CT"
        fi
        ;;
    aarch64|arm64)
        # NEON fait partie de la base AArch64.
        ;;
    *)
        SILLAGE_DEFS="-DSL_REPLI_NON_CT"
        ;;
esac
if [ "$NATIVE" = 1 ]; then
    APP_ARCH_FLAGS="-march=native"
else
    APP_ARCH_FLAGS=""
fi

SILLAGE_CFLAGS="-std=gnu11 -O3 $ARCH_FLAGS $SILLAGE_DEFS -fopenmp"
FLAGS_MARK="$SILLAGE_OBJ/.build-flags"
if [ "$(cat "$FLAGS_MARK" 2>/dev/null || true)" != "$SILLAGE_CFLAGS" ]; then
    rm -f "$SILLAGE_OBJ"/*.o "$SILLAGE_LIB"
    printf '%s' "$SILLAGE_CFLAGS" > "$FLAGS_MARK"
fi

SILLAGE_OBJS=()
NEED_AR=0
if [ ! -f "$SILLAGE_LIB" ]; then
    NEED_AR=1
fi
for src in "${SILLAGE_SRCS[@]}"; do
    obj="$SILLAGE_OBJ/${src%.c}.o"
    SILLAGE_OBJS+=("$obj")
    rebuild=0
    if [ ! -f "$obj" ] || [ "$SILLAGE_DIR/$src" -nt "$obj" ]; then
        rebuild=1
    else
        for hdr in "${SILLAGE_HDRS[@]}"; do
            if [ -f "$SILLAGE_DIR/$hdr" ] && [ "$SILLAGE_DIR/$hdr" -nt "$obj" ]; then
                rebuild=1
                break
            fi
        done
    fi
    if [ "$rebuild" = 1 ]; then
        echo "→ Compilation SILLAGE : $src"
        "$CC" $SILLAGE_CFLAGS -I"$SILLAGE_DIR" \
              -c "$SILLAGE_DIR/$src" -o "$obj"
        NEED_AR=1
    fi
done
if [ "$NEED_AR" = 1 ]; then
    ar rcs "$SILLAGE_LIB" "${SILLAGE_OBJS[@]}"
fi

# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------
X11_LINK="-lX11"
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists x11 2>/dev/null; then
    X11_LINK="$(pkg-config --libs x11)"
elif [ ! -e /usr/lib/x86_64-linux-gnu/libX11.so ] && \
     [ ! -e /usr/lib/aarch64-linux-gnu/libX11.so ] && \
     [ ! -e /usr/lib64/libX11.so ]; then
    X11_LINK="-l:libX11.so.6"
fi

echo "→ Compilation de SILLAGE Transfer…"
"$CC" -std=c11 -O2 $APP_ARCH_FLAGS -Wall -Wextra \
      -DSILLAGE_WEBRTC=1 \
      -I"$RAYLIB_DIR/include" -I"$SILLAGE_DIR" -I"$LDC_INC" \
      "$ROOT/sillage_transfer.c" \
      -o "$OUT" \
      "$RAYLIB_DIR/lib/libraylib.a" "$SILLAGE_LIB" \
      "${LDC_LIBS[@]}" \
      -lssl -lcrypto "$X11_LINK" -lpthread -lm -ldl -lrt -fopenmp -lstdc++

echo "✓ Binaire : $OUT ($(du -h "$OUT" | cut -f1))"
echo "  Lancer :  ./sillage-transfer"
echo "  Tester :  ./sillage-transfer --selftest"

if [ "$PACKAGE" = 1 ]; then
    STAGE="$DEPS/package/sillage-transfer"
    ARCHIVE="$ROOT/sillage-transfer-src.tar.gz"
    rm -rf "$DEPS/package"
    mkdir -p "$STAGE/sillage/c"
    cp "$ROOT/sillage_transfer.c" "$ROOT/build.sh" "$ROOT/README.md" "$STAGE/"
    for f in "${SILLAGE_SRCS[@]}" "${SILLAGE_HDRS[@]}"; do
        cp "$SILLAGE_DIR/$f" "$STAGE/sillage/c/"
    done
    chmod +x "$STAGE/build.sh"
    tar -czf "$ARCHIVE" -C "$DEPS/package" sillage-transfer
    echo "✓ Archive source : $ARCHIVE"
    echo "  Sur la machine destinataire : tar xzf sillage-transfer-src.tar.gz"
    echo "                                cd sillage-transfer && ./build.sh"
fi

if [ "$RUN_TEST" = 1 ]; then
    echo
    "$OUT" --selftest
fi
