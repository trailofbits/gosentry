grammar JSON;

json
    : value EOF
    ;

value
    : STRING
    | NUMBER
    | obj
    | arr
    | 'true'
    | 'false'
    | 'null'
    ;

obj
    : '{' pair (',' pair)* '}'
    | '{' '}'
    ;

pair
    : STRING ':' value
    ;

arr
    : '[' value (',' value)* ']'
    | '[' ']'
    ;

STRING
    : '"' (ESC | SAFE_CHAR)* '"'
    ;

fragment SAFE_CHAR
    : [a-zA-Z0-9 _.,:;!?@/()-]
    ;

fragment ESC
    : '\\' ('"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | UNICODE)
    ;

fragment UNICODE
    : 'u' HEX HEX HEX HEX
    ;

fragment HEX
    : [0-9a-fA-F]
    ;

NUMBER
    : '-'? INT ('.' [0-9]+)? EXP?
    ;

fragment INT
    : '0'
    | [1-9] [0-9]*
    ;

fragment EXP
    : [eE] [+-]? [0-9]+
    ;

WS
    : [ \t\r\n]+ -> skip
    ;
