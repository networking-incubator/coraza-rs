//! Token folding: reduces the token stream to at most [`MAX_TOKENS`] tokens
//! by merging and dropping the ones that do not change what a statement is.
//!
//! This follows upstream's `libinjection_sqli_fold` step for step. The rules
//! work on a window of slots that is truncated and re-scanned in place, and
//! which token a rule drops depends on exactly that bookkeeping.

use super::keywords::lookup_word;
use super::token::{TOKEN_SIZE, Token, TokenType as T};
use super::{MAX_TOKENS, State};

/// Words that are functions when called, but common enough as column names
/// to be barewords otherwise.
const FUNCTION_LIKE_WORDS: [&[u8]; 11] = [
    // T-SQL
    b"USER_ID",
    b"USER_NAME",
    // MySQL
    b"DATABASE",
    b"PASSWORD",
    b"USER",
    // Words that act as a variable and are a function.
    b"CURRENT_USER",
    b"CURRENT_DATE",
    b"CURRENT_TIME",
    b"CURRENT_TIMESTAMP",
    b"LOCALTIME",
    b"LOCALTIMESTAMP",
];

impl State<'_> {
    /// Reads the next token into slot `index`, clearing the slot at the end
    /// of input. Returns whether there was a token.
    fn tokenize_into(&mut self, index: usize) -> bool {
        self.lexer.next_into(&mut self.tokens[index])
    }

    /// Reads tokens into slot `pos` until `pos - left` reaches `want`,
    /// setting comments aside rather than counting them.
    fn fill(
        &mut self,
        want: usize,
        pos: &mut usize,
        left: usize,
        more: &mut bool,
        last_comment: &mut Token,
    ) {
        while *more && *pos <= MAX_TOKENS && *pos - left < want {
            *more = self.tokenize_into(*pos);
            if *more {
                if self.tokens[*pos].ty == T::Comment {
                    *last_comment = self.tokens[*pos];
                } else {
                    last_comment.ty = T::Null;
                    *pos += 1;
                }
            }
        }
    }

    /// Merges the tokens at `left` and `left + 1` if together they form a
    /// known phrase, e.g. "UNION" + "ALL".
    fn merge_words(&mut self, left: usize) -> bool {
        let (a, b) = (&self.tokens[left], &self.tokens[left + 1]);
        if !matches!(
            a.ty,
            T::Keyword
                | T::Bareword
                | T::Operator
                | T::Union
                | T::Function
                | T::Expression
                | T::Tsql
                | T::SqlType
        ) {
            return false;
        }
        if !matches!(
            b.ty,
            T::Keyword
                | T::Bareword
                | T::Operator
                | T::Union
                | T::Function
                | T::Expression
                | T::Tsql
                | T::SqlType
                | T::LogicOperator
        ) {
            return false;
        }

        // One more for the space in the middle; the phrase has to fit a token.
        let len = a.len + b.len + 1;
        if len >= TOKEN_SIZE {
            return false;
        }
        let mut phrase = [0; TOKEN_SIZE];
        phrase[..a.len].copy_from_slice(a.value());
        phrase[a.len] = b' ';
        phrase[a.len + 1..len].copy_from_slice(b.value());
        let phrase = &phrase[..len];
        let pos = a.pos;

        match lookup_word(phrase) {
            Some(ty) => {
                self.tokens[left].assign(ty, pos, phrase);
                true
            }
            None => false,
        }
    }

    /// Tokenizes and folds the input, returning how many of the leading
    /// slots hold the result.
    #[expect(
        clippy::if_same_then_else,
        reason = "one branch per upstream rule, in upstream's order"
    )]
    pub fn fold(&mut self) -> usize {
        let mut last_comment = Token::default();
        // Where the next token goes.
        let mut pos = 0;
        // How many tokens are already folded, i.e. part of the fingerprint.
        let mut left = 0;
        let mut more = true;

        // Skip all initial comments, left parens and unary operators.
        while more {
            more = self.tokenize_into(0);
            let current = &self.tokens[0];
            if !(matches!(current.ty, T::Comment | T::LeftParens | T::SqlType)
                || current.is_unary_op())
            {
                break;
            }
        }
        if !more {
            // The input was only comments, unary operators or '('.
            return 0;
        }
        pos += 1;

        loop {
            // With all the tokens there is room for, a few five-token
            // shapes are collapsed to start over from their first token.
            if pos >= MAX_TOKENS {
                let t = &self.tokens;
                if matches!(
                    (t[0].ty, t[1].ty, t[2].ty, t[3].ty, t[4].ty),
                    (
                        T::Number,
                        T::Operator | T::Comma,
                        T::LeftParens,
                        T::Number,
                        T::RightParens
                    ) | (
                        T::Bareword,
                        T::Operator,
                        T::LeftParens,
                        T::Bareword | T::Number,
                        T::RightParens
                    ) | (
                        T::Number,
                        T::RightParens,
                        T::Comma,
                        T::LeftParens,
                        T::Number
                    ) | (
                        T::Bareword,
                        T::RightParens,
                        T::Operator,
                        T::LeftParens,
                        T::Bareword
                    )
                ) {
                    if pos > MAX_TOKENS {
                        self.tokens[1] = self.tokens[MAX_TOKENS];
                        pos = 2;
                    } else {
                        pos = 1;
                    }
                    left = 0;
                }
            }

            if !more || left >= MAX_TOKENS {
                left = pos;
                break;
            }

            // Get up to two tokens.
            self.fill(2, &mut pos, left, &mut more, &mut last_comment);
            if pos - left < 2 {
                left = pos;
                continue;
            }

            let (a, b) = (&self.tokens[left], &self.tokens[left + 1]);

            if a.ty == T::String && b.ty == T::String {
                // "foo" "bar" is valid SQL: ignore the second string.
                pos -= 1;
                continue;
            } else if a.ty == T::Semicolon && b.ty == T::Semicolon {
                // Fold away repeated semicolons.
                pos -= 1;
                continue;
            } else if matches!(a.ty, T::Operator | T::LogicOperator)
                && (b.is_unary_op() || b.ty == T::SqlType)
            {
                pos -= 1;
                left = 0;
                continue;
            } else if a.ty == T::LeftParens && b.is_unary_op() {
                pos -= 1;
                left = left.saturating_sub(1);
                continue;
            }

            if self.merge_words(left) {
                pos -= 1;
                left = left.saturating_sub(1);
                continue;
            }

            // Merging borrows the tokens mutably, so the rules that come
            // after it take a fresh look at them.
            let (a, b) = (&self.tokens[left], &self.tokens[left + 1]);
            if a.ty == T::Semicolon
                && b.ty == T::Function
                && matches!(b.byte(0), b'I' | b'i')
                && matches!(b.byte(1), b'F' | b'f')
            {
                // IF is normally a function, except in T-SQL where it can
                // be a control flow statement: "; IF 1=1 ...".
                self.tokens[left + 1].ty = T::Tsql;
                continue;
            } else if matches!(a.ty, T::Bareword | T::Variable)
                && b.ty == T::LeftParens
                && FUNCTION_LIKE_WORDS.iter().any(|word| a.is_word(word))
            {
                self.tokens[left].ty = T::Function;
                continue;
            } else if a.ty == T::Keyword && (a.is_word(b"IN") || a.is_word(b"NOT IN")) {
                // "IN (" is an operator. Anything else, e.g. MySQL's
                // "IN BOOLEAN MODE", leaves it a word to merge later.
                self.tokens[left].ty = if b.ty == T::LeftParens {
                    T::Operator
                } else {
                    T::Bareword
                };
                continue;
            } else if a.ty == T::Operator && (a.is_word(b"LIKE") || a.is_word(b"NOT LIKE")) {
                // "LIKE(" is a function call.
                if b.ty == T::LeftParens {
                    self.tokens[left].ty = T::Function;
                }
            } else if a.ty == T::SqlType
                && matches!(
                    b.ty,
                    T::Bareword
                        | T::Number
                        | T::SqlType
                        | T::LeftParens
                        | T::Function
                        | T::Variable
                        | T::String
                )
            {
                self.tokens[left] = *b;
                pos -= 1;
                left = 0;
                continue;
            } else if a.ty == T::Collate && b.ty == T::Bareword {
                // There are too many collations to list: a bareword with
                // an '_' after COLLATE is taken to be one.
                if b.c_str().contains(&b'_') {
                    self.tokens[left + 1].ty = T::SqlType;
                    left = 0;
                }
            } else if a.ty == T::Backslash {
                if b.is_arithmetic_op() {
                    // T-SQL parses "\%1" as "0 % 1".
                    self.tokens[left].ty = T::Number;
                } else {
                    // ... and "\1" as "1": drop the backslash.
                    self.tokens[left] = *b;
                    pos -= 1;
                }
                left = 0;
                continue;
            } else if (a.ty == T::LeftParens && b.ty == T::LeftParens)
                || (a.ty == T::RightParens && b.ty == T::RightParens)
            {
                pos -= 1;
                left = 0;
                continue;
            } else if a.ty == T::LeftBrace && b.ty == T::Bareword {
                // MySQL accepts "select { ``.``.id }". Folding cannot look
                // far enough to tell that apart, and "{ ``" is rare enough
                // to ban outright.
                if b.len == 0 {
                    self.tokens[left + 1].ty = T::Evil;
                    return left + 2;
                }
                // ODBC's "{foo expr}" is "expr": strip the "{ foo".
                left = 0;
                pos -= 2;
                continue;
            } else if b.ty == T::RightBrace {
                pos -= 1;
                left = 0;
                continue;
            }

            // No two-token rule matched: get one more token.
            self.fill(3, &mut pos, left, &mut more, &mut last_comment);
            if pos - left < 3 {
                left = pos;
                continue;
            }

            let (a, b, c) = (
                &self.tokens[left],
                &self.tokens[left + 1],
                &self.tokens[left + 2],
            );

            if a.ty == T::Number && b.ty == T::Operator && c.ty == T::Number {
                pos -= 2;
                left = 0;
                continue;
            } else if a.ty == T::Operator && b.ty != T::LeftParens && c.ty == T::Operator {
                pos -= 2;
                left = 0;
                continue;
            } else if a.ty == T::LogicOperator && c.ty == T::LogicOperator {
                pos -= 2;
                left = 0;
                continue;
            } else if a.ty == T::Variable
                && b.ty == T::Operator
                && matches!(c.ty, T::Variable | T::Number | T::Bareword)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if matches!(a.ty, T::Bareword | T::Number)
                && b.ty == T::Operator
                && matches!(c.ty, T::Number | T::Bareword)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if matches!(a.ty, T::Bareword | T::Number | T::Variable | T::String)
                && b.ty == T::Operator
                && b.c_str() == b"::"
                && c.ty == T::SqlType
            {
                // A PostgreSQL cast.
                pos -= 2;
                left = 0;
                continue;
            } else if matches!(a.ty, T::Bareword | T::Number | T::String | T::Variable)
                && b.ty == T::Comma
                && matches!(c.ty, T::Number | T::Bareword | T::String | T::Variable)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if matches!(a.ty, T::Expression | T::Group | T::Comma)
                && b.is_unary_op()
                && c.ty == T::LeftParens
            {
                // "SELECT + (", "LIMIT + (": remove the unary operator.
                self.tokens[left + 1] = *c;
                pos -= 1;
                left = 0;
                continue;
            } else if matches!(a.ty, T::Keyword | T::Expression | T::Group)
                && b.is_unary_op()
                && matches!(
                    c.ty,
                    T::Number | T::Bareword | T::Variable | T::String | T::Function
                )
            {
                // "select - 1": remove the unary operator.
                self.tokens[left + 1] = *c;
                pos -= 1;
                left = 0;
                continue;
            } else if a.ty == T::Comma
                && b.is_unary_op()
                && matches!(c.ty, T::Number | T::Bareword | T::Variable | T::String)
            {
                // ", -1" becomes ",1", and all three tokens are dropped to
                // back up and see whether "1,-1" folds further into "1".
                self.tokens[left + 1] = *c;
                left = 0;
                pos -= 3;
                continue;
            } else if a.ty == T::Comma && b.is_unary_op() && c.ty == T::Function {
                // "1,-sin(1)" becomes "1,sin(1)": only the unary operator
                // goes, or this would end up as "1 (1)".
                self.tokens[left + 1] = *c;
                pos -= 1;
                left = 0;
                continue;
            } else if a.ty == T::Bareword && b.ty == T::Dot && c.ty == T::Bareword {
                // Typically "databasename.table": ignore the ".n".
                pos -= 2;
                left = 0;
                continue;
            } else if a.ty == T::Expression && b.ty == T::Dot && c.ty == T::Bareword {
                // "select . `foo`" is "select `foo`".
                self.tokens[left + 1] = *c;
                pos -= 1;
                left = 0;
                continue;
            } else if a.ty == T::Function
                && b.ty == T::LeftParens
                && c.ty != T::RightParens
                && a.is_word(b"USER")
            {
                // USER() takes no arguments, so "User(foo)" is not it.
                self.tokens[left].ty = T::Bareword;
            }

            // Nothing folded: the left-most token is final. Carry on with
            // the two that are left rather than fetching another.
            left += 1;
        }

        // With four tokens or fewer, a trailing comment is added back.
        if left < MAX_TOKENS && last_comment.ty == T::Comment {
            self.tokens[left] = last_comment;
            left += 1;
        }

        // A sixth token is sometimes read to decide the type of the fifth.
        left.min(MAX_TOKENS)
    }
}
