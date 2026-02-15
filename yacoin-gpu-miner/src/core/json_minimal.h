/*
 * Minimal JSON parser for Stratum protocol
 * Only handles the specific JSON-RPC messages needed for mining
 */

#ifndef JSON_MINIMAL_H
#define JSON_MINIMAL_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define JSON_MAX_TOKENS 64
#define JSON_MAX_STRING 256

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} JsonType;

typedef struct JsonValue {
    JsonType type;
    union {
        int boolVal;
        double numVal;
        char strVal[JSON_MAX_STRING];
        struct {
            struct JsonValue* items;
            int count;
        } array;
    } data;
} JsonValue;

// Simple JSON string parser
static inline const char* json_skip_whitespace(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static inline const char* json_parse_string(const char* p, char* out, int maxLen) {
    if (*p != '"') return NULL;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < maxLen - 1) {
        if (*p == '\\' && *(p+1)) {
            p++;
            switch (*p) {
                case 'n': out[i++] = '\n'; break;
                case 't': out[i++] = '\t'; break;
                case 'r': out[i++] = '\r'; break;
                case '"': out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    if (*p == '"') p++;
    return p;
}

// Find a key in JSON object and return pointer to its value
static inline const char* json_find_key(const char* json, const char* key) {
    char searchKey[JSON_MAX_STRING];
    snprintf(searchKey, sizeof(searchKey), "\"%s\"", key);

    const char* p = strstr(json, searchKey);
    if (!p) return NULL;

    p += strlen(searchKey);
    p = json_skip_whitespace(p);
    if (*p != ':') return NULL;
    p++;
    p = json_skip_whitespace(p);
    return p;
}

// Get string value from JSON
static inline int json_get_string(const char* json, const char* key, char* out, int maxLen) {
    const char* p = json_find_key(json, key);
    if (!p) return -1;

    if (*p != '"') return -1;
    json_parse_string(p, out, maxLen);
    return 0;
}

// Get integer value from JSON
static inline int json_get_int(const char* json, const char* key, int* out) {
    const char* p = json_find_key(json, key);
    if (!p) return -1;

    *out = atoi(p);
    return 0;
}

// Get double value from JSON
static inline int json_get_double(const char* json, const char* key, double* out) {
    const char* p = json_find_key(json, key);
    if (!p) return -1;

    *out = atof(p);
    return 0;
}

// Get boolean value from JSON
static inline int json_get_bool(const char* json, const char* key, int* out) {
    const char* p = json_find_key(json, key);
    if (!p) return -1;

    if (strncmp(p, "true", 4) == 0) {
        *out = 1;
        return 0;
    } else if (strncmp(p, "false", 5) == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

// Get array element at index (returns pointer to start of element)
static inline const char* json_array_get(const char* arrayStart, int index) {
    const char* p = json_skip_whitespace(arrayStart);
    if (*p != '[') return NULL;
    p++;
    p = json_skip_whitespace(p);

    int depth = 0;
    int currentIndex = 0;
    const char* elementStart = p;

    while (*p) {
        if (*p == '"') {
            p++;
            while (*p && !(*p == '"' && *(p-1) != '\\')) p++;
            if (*p) p++;
            continue;
        }

        if (*p == '[' || *p == '{') {
            depth++;
        } else if (*p == ']' || *p == '}') {
            if (depth == 0 && *p == ']') {
                if (currentIndex == index) return elementStart;
                return NULL;
            }
            depth--;
        } else if (*p == ',' && depth == 0) {
            if (currentIndex == index) return elementStart;
            currentIndex++;
            p++;
            p = json_skip_whitespace(p);
            elementStart = p;
            continue;
        }
        p++;
    }

    return NULL;
}

// Get string from array element
static inline int json_array_get_string(const char* arrayStart, int index, char* out, int maxLen) {
    const char* elem = json_array_get(arrayStart, index);
    if (!elem) return -1;
    elem = json_skip_whitespace(elem);
    if (*elem != '"') return -1;
    json_parse_string(elem, out, maxLen);
    return 0;
}

// Get int from array element
static inline int json_array_get_int(const char* arrayStart, int index, int* out) {
    const char* elem = json_array_get(arrayStart, index);
    if (!elem) return -1;
    *out = atoi(elem);
    return 0;
}

// Get double from array element
static inline int json_array_get_double(const char* arrayStart, int index, double* out) {
    const char* elem = json_array_get(arrayStart, index);
    if (!elem) return -1;
    *out = atof(elem);
    return 0;
}

// Get bool from array element
static inline int json_array_get_bool(const char* arrayStart, int index, int* out) {
    const char* elem = json_array_get(arrayStart, index);
    if (!elem) return -1;
    elem = json_skip_whitespace(elem);
    if (strncmp(elem, "true", 4) == 0) {
        *out = 1;
        return 0;
    } else if (strncmp(elem, "false", 5) == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

// Count array elements
static inline int json_array_length(const char* arrayStart) {
    const char* p = json_skip_whitespace(arrayStart);
    if (*p != '[') return -1;
    p++;
    p = json_skip_whitespace(p);

    if (*p == ']') return 0;

    int depth = 0;
    int count = 1;

    while (*p) {
        if (*p == '"') {
            p++;
            while (*p && !(*p == '"' && *(p-1) != '\\')) p++;
            if (*p) p++;
            continue;
        }

        if (*p == '[' || *p == '{') {
            depth++;
        } else if (*p == ']' || *p == '}') {
            if (depth == 0 && *p == ']') {
                return count;
            }
            depth--;
        } else if (*p == ',' && depth == 0) {
            count++;
        }
        p++;
    }

    return count;
}

#endif // JSON_MINIMAL_H
