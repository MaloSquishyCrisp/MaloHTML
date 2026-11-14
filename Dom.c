/**
 * ============================================================================
 * Dom.c - ALL-IN-ONE HTML PARSER, CSS ENGINE & DOM TREE BUILDER
 * ============================================================================
 * Architecture: Arena-Managed DOM Tree + Cascading Style Resolver
 * 
 * DESIGN GOALS:
 * 1. Security Compliance: Bounded string operations (snprintf/strncpy), strict
 *    recursion/depth guards, and maximum node limits to prevent DoS/overflows.
 * 2. Speed: Flat pointer-based DOM tree with direct tag/ID/class matching and
 *    fast cascade resolution.
 * 3. Self-Contained: Zero external dependencies beyond standard C libraries.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

// ==========================================
// 0. CLEAR SETTINGS & SECURITY CONFIGURATION
// ==========================================
#define MAX_HTML_INPUT_SIZE     131072  // 128 KB max HTML payload
#define MAX_CSS_INPUT_SIZE      65536   // 64 KB max CSS payload
#define MAX_DOM_NODES           4096    // Prevent memory exhaustion (DoS)
#define MAX_DOM_DEPTH           128     // Prevent stack overflow on deeply nested tags
#define MAX_TAG_NAME_LEN        32
#define MAX_ATTR_COUNT          16
#define MAX_ATTR_NAME_LEN       32
#define MAX_ATTR_VAL_LEN        128
#define MAX_TEXT_LEN            512
#define MAX_CSS_RULES           256
#define MAX_CSS_DECLS_PER_RULE  32
#define MAX_SELECTOR_LEN        64
#define MAX_PROP_LEN            32
#define MAX_VAL_LEN             64

// ==========================================
// 1. DATA STRUCTURES (DOM & CSS)
// ==========================================

typedef enum {
    NODE_DOCUMENT,
    NODE_ELEMENT,
    NODE_TEXT
} NodeType;

typedef struct {
    char name[MAX_ATTR_NAME_LEN];
    char value[MAX_ATTR_VAL_LEN];
} Attribute;

typedef struct {
    char property[MAX_PROP_LEN];
    char value[MAX_VAL_LEN];
} CSSDeclaration;

typedef struct {
    char selector[MAX_SELECTOR_LEN]; // Supports: tag, .class, #id, *
    int specificity;                 // 100 for #id, 10 for .class, 1 for tag, 0 for *
    CSSDeclaration declarations[MAX_CSS_DECLS_PER_RULE];
    int decl_count;
} CSSRule;

typedef struct {
    CSSRule rules[MAX_CSS_RULES];
    int rule_count;
} StyleSheet;

typedef struct DOMNode {
    NodeType type;
    char tag_name[MAX_TAG_NAME_LEN];
    char text_content[MAX_TEXT_LEN];
    
    Attribute attributes[MAX_ATTR_COUNT];
    int attr_count;

    // Computed Styles resolved from CSS rules + inline style attribute
    CSSDeclaration computed_styles[MAX_CSS_DECLS_PER_RULE];
    int computed_style_count;

    // Tree Pointers
    struct DOMNode* parent;
    struct DOMNode* first_child;
    struct DOMNode* last_child;
    struct DOMNode* next_sibling;
} DOMNode;

// Engine Context (Tracks all allocations for safe O(N) teardown)
typedef struct {
    DOMNode* node_pool[MAX_DOM_NODES];
    int total_nodes;
    StyleSheet stylesheet;
} DOMEngine;

// ==========================================
// 2. ENGINE LIFECYCLE & MEMORY MANAGEMENT
// ==========================================

void dom_engine_init(DOMEngine* engine) {
    memset(engine, 0, sizeof(DOMEngine));
}

void dom_engine_destroy(DOMEngine* engine) {
    for (int i = 0; i < engine->total_nodes; i++) {
        free(engine->node_pool[i]);
        engine->node_pool[i] = NULL;
    }
    engine->total_nodes = 0;
}

DOMNode* dom_create_node(DOMEngine* engine, NodeType type) {
    if (engine->total_nodes >= MAX_DOM_NODES) {
        fprintf(stderr, "[SecurityError] Maximum DOM node limit (%d) reached.\n", MAX_DOM_NODES);
        return NULL;
    }
    DOMNode* node = (DOMNode*)calloc(1, sizeof(DOMNode));
    if (!node) {
        fprintf(stderr, "[MemoryError] Failed to allocate DOMNode.\n");
        return NULL;
    }
    node->type = type;
    engine->node_pool[engine->total_nodes++] = node;
    return node;
}

// ==========================================
// 3. DOM MANIPULATION APIS (JS-STYLE)
// ==========================================

DOMNode* dom_create_element(DOMEngine* engine, const char* tag_name) {
    DOMNode* node = dom_create_node(engine, NODE_ELEMENT);
    if (!node) return NULL;
    strncpy(node->tag_name, tag_name, MAX_TAG_NAME_LEN - 1);
    node->tag_name[MAX_TAG_NAME_LEN - 1] = '\0';
    return node;
}

DOMNode* dom_create_text_node(DOMEngine* engine, const char* text) {
    DOMNode* node = dom_create_node(engine, NODE_TEXT);
    if (!node) return NULL;
    strncpy(node->text_content, text, MAX_TEXT_LEN - 1);
    node->text_content[MAX_TEXT_LEN - 1] = '\0';
    return node;
}

void dom_append_child(DOMNode* parent, DOMNode* child) {
    if (!parent || !child) return;
    child->parent = parent;
    if (!parent->first_child) {
        parent->first_child = child;
        parent->last_child = child;
    } else {
        parent->last_child->next_sibling = child;
        parent->last_child = child;
    }
}

void dom_set_attribute(DOMNode* node, const char* name, const char* value) {
    if (!node || node->type != NODE_ELEMENT) return;

    // Check if attribute already exists and update it
    for (int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attributes[i].name, name) == 0) {
            strncpy(node->attributes[i].value, value, MAX_ATTR_VAL_LEN - 1);
            node->attributes[i].value[MAX_ATTR_VAL_LEN - 1] = '\0';
            return;
        }
    }

    if (node->attr_count >= MAX_ATTR_COUNT) {
        fprintf(stderr, "[SecurityWarning] Max attributes reached on <%s>.\n", node->tag_name);
        return;
    }

    Attribute* attr = &node->attributes[node->attr_count++];
    strncpy(attr->name, name, MAX_ATTR_NAME_LEN - 1);
    attr->name[MAX_ATTR_NAME_LEN - 1] = '\0';
    strncpy(attr->value, value, MAX_ATTR_VAL_LEN - 1);
    attr->value[MAX_ATTR_VAL_LEN - 1] = '\0';
}

const char* dom_get_attribute(const DOMNode* node, const char* name) {
    if (!node || node->type != NODE_ELEMENT) return NULL;
    for (int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attributes[i].name, name) == 0) {
            return node->attributes[i].value;
        }
    }
    return NULL;
}

DOMNode* dom_get_element_by_id(DOMNode* root, const char* id) {
    if (!root) return NULL;
    if (root->type == NODE_ELEMENT) {
        const char* node_id = dom_get_attribute(root, "id");
        if (node_id && strcmp(node_id, id) == 0) {
            return root;
        }
    }
    for (DOMNode* child = root->first_child; child != NULL; child = child->next_sibling) {
        DOMNode* found = dom_get_element_by_id(child, id);
        if (found) return found;
    }
    return NULL;
}

// ==========================================
// 4. CSS PARSER & CASCADE RESOLVER
// ==========================================

static void trim_whitespace(char* str) {
    char* start = str;
    while (isspace((unsigned char)*start)) start++;
    if (*start == 0) {
        str[0] = '\0';
        return;
    }
    char* end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    memmove(str, start, end - start + 2);
}

void css_parse(DOMEngine* engine, const char* css_text) {
    if (!css_text) return;
    size_t len = strlen(css_text);
    if (len > MAX_CSS_INPUT_SIZE) {
        fprintf(stderr, "[SecurityError] CSS payload exceeds maximum size.\n");
        return;
    }

    StyleSheet* sheet = &engine->stylesheet;
    size_t i = 0;

    while (i < len && sheet->rule_count < MAX_CSS_RULES) {
        // Skip whitespace and comments
        while (i < len && isspace((unsigned char)css_text[i])) i++;
        if (i + 1 < len && css_text[i] == '/' && css_text[i + 1] == '*') {
            i += 2;
            while (i + 1 < len && !(css_text[i] == '*' && css_text[i + 1] == '/')) i++;
            i += 2;
            continue;
        }
        if (i >= len) break;

        // Read Selector up to '{'
        CSSRule* rule = &sheet->rules[sheet->rule_count];
        memset(rule, 0, sizeof(CSSRule));

        int sel_idx = 0;
        while (i < len && css_text[i] != '{') {
            if (sel_idx < MAX_SELECTOR_LEN - 1) {
                rule->selector[sel_idx++] = css_text[i];
            }
            i++;
        }
        rule->selector[sel_idx] = '\0';
        trim_whitespace(rule->selector);

        if (i >= len || css_text[i] != '{') break;
        i++; // Skip '{'

        // Calculate Selector Specificity
        if (rule->selector[0] == '#') rule->specificity = 100;
        else if (rule->selector[0] == '.') rule->specificity = 10;
        else if (rule->selector[0] == '*') rule->specificity = 0;
        else rule->specificity = 1;

        // Parse Declarations inside '{ ... }'
        while (i < len && css_text[i] != '}') {
            while (i < len && isspace((unsigned char)css_text[i])) i++;
            if (css_text[i] == '}') break;

            char prop[MAX_PROP_LEN] = {0};
            char val[MAX_VAL_LEN] = {0};
            int p_idx = 0, v_idx = 0;

            // Property name
            while (i < len && css_text[i] != ':' && css_text[i] != '}') {
                if (p_idx < MAX_PROP_LEN - 1) prop[p_idx++] = css_text[i];
                i++;
            }
            if (i < len && css_text[i] == ':') i++; // Skip ':'

            // Property value
            while (i < len && css_text[i] != ';' && css_text[i] != '}') {
                if (v_idx < MAX_VAL_LEN - 1) val[v_idx++] = css_text[i];
                i++;
            }
            if (i < len && css_text[i] == ';') i++; // Skip ';'

            trim_whitespace(prop);
            trim_whitespace(val);

            if (strlen(prop) > 0 && strlen(val) > 0 && rule->decl_count < MAX_CSS_DECLS_PER_RULE) {
                CSSDeclaration* decl = &rule->declarations[rule->decl_count++];
                strncpy(decl->property, prop, MAX_PROP_LEN - 1);
                strncpy(decl->value, val, MAX_VAL_LEN - 1);
            }
        }
        if (i < len && css_text[i] == '}') i++; // Skip '}'
        sheet->rule_count++;
    }
}

static bool css_matches_selector(const DOMNode* node, const char* selector) {
    if (!node || node->type != NODE_ELEMENT || !selector || selector[0] == '\0') return false;

    if (strcmp(selector, "*") == 0) return true;

    // ID Selector (#header)
    if (selector[0] == '#') {
        const char* id = dom_get_attribute(node, "id");
        return (id && strcmp(id, selector + 1) == 0);
    }

    // Class Selector (.btn) - checks space-separated class list
    if (selector[0] == '.') {
        const char* class_attr = dom_get_attribute(node, "class");
        if (!class_attr) return false;
        
        char buffer[MAX_ATTR_VAL_LEN];
        strncpy(buffer, class_attr, MAX_ATTR_VAL_LEN - 1);
        buffer[MAX_ATTR_VAL_LEN - 1] = '\0';

        char* token = strtok(buffer, " \t\n\r");
        while (token != NULL) {
            if (strcmp(token, selector + 1) == 0) return true;
            token = strtok(NULL, " \t\n\r");
        }
        return false;
    }

    // Tag Selector (div, p, h1)
    return strcmp(node->tag_name, selector) == 0;
}

static void apply_style_declaration(DOMNode* node, const char* prop, const char* val) {
    for (int i = 0; i < node->computed_style_count; i++) {
        if (strcmp(node->computed_styles[i].property, prop) == 0) {
            strncpy(node->computed_styles[i].value, val, MAX_VAL_LEN - 1);
            node->computed_styles[i].value[MAX_VAL_LEN - 1] = '\0';
            return;
        }
    }
    if (node->computed_style_count < MAX_CSS_DECLS_PER_RULE) {
        CSSDeclaration* decl = &node->computed_styles[node->computed_style_count++];
        strncpy(decl->property, prop, MAX_PROP_LEN - 1);
        strncpy(decl->value, val, MAX_VAL_LEN - 1);
    }
}

void dom_compute_styles(DOMEngine* engine, DOMNode* node) {
    if (!node) return;

    if (node->type == NODE_ELEMENT) {
        node->computed_style_count = 0;

        // 1. Apply matching stylesheet rules ordered by specificity (0 -> 1 -> 10 -> 100)
        int target_specificities[] = {0, 1, 10, 100};
        for (int s = 0; s < 4; s++) {
            int spec = target_specificities[s];
            for (int r = 0; r < engine->stylesheet.rule_count; r++) {
                CSSRule* rule = &engine->stylesheet.rules[r];
                if (rule->specificity == spec && css_matches_selector(node, rule->selector)) {
                    for (int d = 0; d < rule->decl_count; d++) {
                        apply_style_declaration(node, rule->declarations[d].property, rule->declarations[d].value);
                    }
                }
            }
        }

        // 2. Apply inline style="..." attribute (highest priority)
        const char* inline_style = dom_get_attribute(node, "style");
        if (inline_style) {
            char buffer[MAX_ATTR_VAL_LEN];
            strncpy(buffer, inline_style, MAX_ATTR_VAL_LEN - 1);
            buffer[MAX_ATTR_VAL_LEN - 1] = '\0';

            char* pair = strtok(buffer, ";");
            while (pair != NULL) {
                char* colon = strchr(pair, ':');
                if (colon) {
                    *colon = '\0';
                    char* prop = pair;
                    char* val = colon + 1;
                    trim_whitespace(prop);
                    trim_whitespace(val);
                    if (strlen(prop) > 0 && strlen(val) > 0) {
                        apply_style_declaration(node, prop, val);
                    }
                }
                pair = strtok(NULL, ";");
            }
        }
    }

    // Recursively compute styles for children
    for (DOMNode* child = node->first_child; child != NULL; child = child->next_sibling) {
        dom_compute_styles(engine, child);
    }
}

// ==========================================
// 5. HTML PARSER & DOM TREE CONSTRUCTOR
// ==========================================

static bool is_void_element(const char* tag) {
    const char* voids[] = {"br", "hr", "img", "input", "meta", "link", NULL};
    for (int i = 0; voids[i] != NULL; i++) {
        if (strcasecmp(tag, voids[i]) == 0) return true;
    }
    return false;
}

DOMNode* html_parse(DOMEngine* engine, const char* html) {
    if (!html) return NULL;
    size_t len = strlen(html);
    if (len > MAX_HTML_INPUT_SIZE) {
        fprintf(stderr, "[SecurityError] HTML payload exceeds maximum size (%d bytes).\n", MAX_HTML_INPUT_SIZE);
        return NULL;
    }

    DOMNode* document = dom_create_node(engine, NODE_DOCUMENT);
    if (!document) return NULL;
    strcpy(document->tag_name, "#document");

    DOMNode* current_parent = document;
    int current_depth = 0;
    size_t i = 0;

    while (i < len) {
        if (html[i] == '<') {
            // 1. HTML Comment <!-- ... -->
            if (i + 3 < len && strncmp(&html[i], "<!--", 4) == 0) {
                i += 4;
                while (i + 2 < len && strncmp(&html[i], "-->", 3) != 0) i++;
                i += 3;
                continue;
            }

            // 2. Closing Tag </tag>
            if (i + 1 < len && html[i + 1] == '/') {
                i += 2;
                char close_tag[MAX_TAG_NAME_LEN] = {0};
                int t_idx = 0;
                while (i < len && html[i] != '>' && !isspace((unsigned char)html[i])) {
                    if (t_idx < MAX_TAG_NAME_LEN - 1) close_tag[t_idx++] = html[i];
                    i++;
                }
                while (i < len && html[i] != '>') i++;
                if (i < len) i++; // Skip '>'

                // Pop back up the tree if matching parent tag
                if (current_parent->parent && strcasecmp(current_parent->tag_name, close_tag) == 0) {
                    current_parent = current_parent->parent;
                    current_depth--;
                }
                continue;
            }

            // 3. Opening Tag <tag attr="val">
            i++; // Skip '<'
            char tag_name[MAX_TAG_NAME_LEN] = {0};
            int t_idx = 0;
            while (i < len && !isspace((unsigned char)html[i]) && html[i] != '>' && html[i] != '/') {
                if (t_idx < MAX_TAG_NAME_LEN - 1) tag_name[t_idx++] = html[i];
                i++;
            }

            DOMNode* elem = dom_create_element(engine, tag_name);
            if (!elem) return document;

            // Parse Attributes
            bool self_closing = false;
            while (i < len && html[i] != '>') {
                while (i < len && isspace((unsigned char)html[i])) i++;
                if (html[i] == '/') {
                    self_closing = true;
                    i++;
                    continue;
                }
                if (html[i] == '>') break;

                char attr_name[MAX_ATTR_NAME_LEN] = {0};
                char attr_val[MAX_ATTR_VAL_LEN] = {0};
                int a_idx = 0, v_idx = 0;

                while (i < len && html[i] != '=' && !isspace((unsigned char)html[i]) && html[i] != '>') {
                    if (a_idx < MAX_ATTR_NAME_LEN - 1) attr_name[a_idx++] = html[i];
                    i++;
                }

                while (i < len && isspace((unsigned char)html[i])) i++;

                if (i < len && html[i] == '=') {
                    i++; // Skip '='
                    while (i < len && isspace((unsigned char)html[i])) i++;
                    if (i < len && (html[i] == '"' || html[i] == '\'')) {
                        char quote = html[i++];
                        while (i < len && html[i] != quote) {
                            if (v_idx < MAX_ATTR_VAL_LEN - 1) attr_val[v_idx++] = html[i];
                            i++;
                        }
                        if (i < len && html[i] == quote) i++;
                    } else {
                        while (i < len && !isspace((unsigned char)html[i]) && html[i] != '>') {
                            if (v_idx < MAX_ATTR_VAL_LEN - 1) attr_val[v_idx++] = html[i];
                            i++;
                        }
                    }
                }

                if (strlen(attr_name) > 0) {
                    dom_set_attribute(elem, attr_name, attr_val);
                }
            }
            if (i < len && html[i] == '>') i++; // Skip '>'

            dom_append_child(current_parent, elem);

            // Descend into element unless self-closing or void
            if (!self_closing && !is_void_element(tag_name)) {
                if (current_depth + 1 >= MAX_DOM_DEPTH) {
                    fprintf(stderr, "[SecurityError] Maximum DOM nesting depth (%d) exceeded.\n", MAX_DOM_DEPTH);
                    return document;
                }
                current_parent = elem;
                current_depth++;
            }
        } else {
            // 4. Text Content Node
            char text_buf[MAX_TEXT_LEN] = {0};
            int txt_idx = 0;
            while (i < len && html[i] != '<') {
                if (txt_idx < MAX_TEXT_LEN - 1) text_buf[txt_idx++] = html[i];
                i++;
            }
            trim_whitespace(text_buf);
            if (strlen(text_buf) > 0) {
                DOMNode* text_node = dom_create_text_node(engine, text_buf);
                if (text_node) {
                    dom_append_child(current_parent, text_node);
                }
            }
        }
    }

    return document;
}

// ==========================================
// 6. TREE SERIALIZER & DEBUG INSPECTOR
// ==========================================

void dom_print_tree(const DOMNode* node, int indent) {
    if (!node) return;

    for (int i = 0; i < indent; i++) printf("  ");

    if (node->type == NODE_DOCUMENT) {
        printf("[Document]\n");
    } else if (node->type == NODE_TEXT) {
        printf("\"%s\"\n", node->text_content);
    } else if (node->type == NODE_ELEMENT) {
        printf("<%s", node->tag_name);
        for (int a = 0; a < node->attr_count; a++) {
            printf(" %s=\"%s\"", node->attributes[a].name, node->attributes[a].value);
        }
        printf(">");

        // Print computed CSS styles inline for inspection
        if (node->computed_style_count > 0) {
            printf("  /* Computed CSS: ");
            for (int s = 0; s < node->computed_style_count; s++) {
                printf("%s: %s; ", node->computed_styles[s].property, node->computed_styles[s].value);
            }
            printf("*/");
        }
        printf("\n");
    }

    for (DOMNode* child = node->first_child; child != NULL; child = child->next_sibling) {
        dom_print_tree(child, indent + 1);
    }
}

// ==========================================
// 7. TEST HARNESS & EXECUTION DEMO
// ==========================================

int main(void) {
    DOMEngine engine;
    dom_engine_init(&engine);

    const char* sample_css =
        "* { box-sizing: border-box; }\n"
        "body { background-color: #121212; color: #ffffff; font-family: sans-serif; }\n"
        ".card { padding: 16px; border-radius: 8px; background-color: #1e1e1e; }\n"
        "#hero-title { color: #00ffcc; font-size: 24px; }\n";

    const char* sample_html =
        "<html>\n"
        "  <body>\n"
        "    <div id=\"main-container\" class=\"card\">\n"
        "      <h1 id=\"hero-title\">Welcome to MiniDOM</h1>\n"
        "      <p style=\"color: #ffaa00;\">Fast, bounded C DOM & CSS engine.</p>\n"
        "      <img src=\"logo.png\" alt=\"Logo\" />\n"
        "    </div>\n"
        "  </body>\n"
        "</html>";

    printf("=== 1. Parsing CSS & HTML ===\n");
    css_parse(&engine, sample_css);
    DOMNode* doc = html_parse(&engine, sample_html);

    printf("=== 2. Dynamic DOM API Manipulation ===\n");
    DOMNode* container = dom_get_element_by_id(doc, "main-container");
    if (container) {
        DOMNode* btn = dom_create_element(&engine, "button");
        dom_set_attribute(btn, "class", "card primary-btn");
        DOMNode* btn_label = dom_create_text_node(&engine, "Click Me");
        dom_append_child(btn, btn_label);
        dom_append_child(container, btn);
    }

    printf("=== 3. Resolving CSS Cascade ===\n");
    dom_compute_styles(&engine, doc);

    printf("=== 4. Rendered DOM + Computed Styles Tree ===\n\n");
    dom_print_tree(doc, 0);

    printf("\n=== 5. Cleaning Up Arena Memory (%d nodes freed) ===\n", engine.total_nodes);
    dom_engine_destroy(&engine);

    return 0;
}
