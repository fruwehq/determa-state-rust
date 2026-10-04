//! Portable CEL guard inspection with the §12 abstract work schedule.
//! This never invokes the ordinary runtime evaluator.

use crate::value::Value;
use cel_parser::ast::operators;
use cel_parser::ast::{EntryExpr, Expr, IdedExpr};
use cel_parser::reference::Val;
use cel_parser::Parser;
use std::collections::BTreeMap;

#[cfg(determa_repository_conformance)]
thread_local! {
    static OBSERVED_GUARDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Repository counter sampled around actual bounded interpreter entries.
#[cfg(determa_repository_conformance)]
pub fn observed_inspection_guards() -> usize {
    OBSERVED_GUARDS.with(std::cell::Cell::get)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InspectionEvaluationError {
    Limit,
    Guard,
}

type EvalResult<T> = Result<T, InspectionEvaluationError>;

fn scalars(value: &str) -> usize {
    value.chars().count()
}

pub(crate) fn value_units(value: &Value) -> usize {
    match value {
        Value::String(value) => 1 + scalars(value),
        Value::List(values) => values.len() + values.iter().map(value_units).sum::<usize>(),
        Value::Map(values) => values
            .iter()
            .map(|(key, item)| 1 + scalars(key) + value_units(item))
            .sum(),
        _ => 1,
    }
}

pub(crate) fn json_units(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::String(value) => 1 + scalars(value),
        serde_json::Value::Array(values) => {
            values.len() + values.iter().map(json_units).sum::<usize>()
        }
        serde_json::Value::Object(values) => values
            .iter()
            .map(|(key, item)| 1 + scalars(key) + json_units(item))
            .sum(),
        _ => 1,
    }
}

fn map_lookup_cost(values: &BTreeMap<String, Value>, key: &str) -> usize {
    1 + scalars(key) + values.keys().map(|key| 1 + scalars(key)).sum::<usize>()
}

fn node_count(expression: &IdedExpr) -> usize {
    1 + match &expression.expr {
        Expr::Call(call) => {
            call.target.as_deref().map_or(0, node_count)
                + call.args.iter().map(node_count).sum::<usize>()
        }
        Expr::List(list) => list.elements.iter().map(node_count).sum(),
        Expr::Map(map) => map
            .entries
            .iter()
            .map(|entry| match &entry.expr {
                EntryExpr::MapEntry(entry) => node_count(&entry.key) + node_count(&entry.value),
                EntryExpr::StructField(entry) => node_count(&entry.value),
            })
            .sum(),
        Expr::Select(select) => node_count(&select.operand),
        Expr::Comprehension(_)
        | Expr::Struct(_)
        | Expr::Unspecified
        | Expr::Ident(_)
        | Expr::Literal(_) => 0,
    }
}

fn parsed_unary_count(expression: &IdedExpr) -> usize {
    let own = usize::from(matches!(&expression.expr, Expr::Call(call)
        if call.func_name == operators::LOGICAL_NOT));
    own + match &expression.expr {
        Expr::Call(call) => {
            call.target.as_deref().map_or(0, parsed_unary_count)
                + call.args.iter().map(parsed_unary_count).sum::<usize>()
        }
        Expr::List(list) => list.elements.iter().map(parsed_unary_count).sum(),
        Expr::Map(map) => map
            .entries
            .iter()
            .map(|entry| match &entry.expr {
                EntryExpr::MapEntry(entry) => {
                    parsed_unary_count(&entry.key) + parsed_unary_count(&entry.value)
                }
                EntryExpr::StructField(entry) => parsed_unary_count(&entry.value),
            })
            .sum(),
        Expr::Select(select) => parsed_unary_count(&select.operand),
        _ => 0,
    }
}

fn source_unary_count(source: &str) -> usize {
    let mut quote = None;
    let mut escaped = false;
    let mut count = 0;
    let mut chars = source.chars().peekable();
    while let Some(character) = chars.next() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '!' && chars.peek() != Some(&'=') {
            count += 1;
        }
    }
    count
}

fn whitespace_end(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn quoted_end(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn grouped_end(bytes: &[u8], start: usize) -> usize {
    let mut stack = vec![bytes[start]];
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => index = quoted_end(bytes, index),
            b'(' | b'[' | b'{' => {
                stack.push(bytes[index]);
                index += 1;
            }
            b')' | b']' | b'}' => {
                stack.pop();
                index += 1;
                if stack.is_empty() {
                    return index;
                }
            }
            _ => index += 1,
        }
    }
    bytes.len()
}

fn unary_operand_end(bytes: &[u8], start: usize) -> usize {
    let mut index = whitespace_end(bytes, start);
    if index >= bytes.len() {
        return index;
    }
    if matches!(bytes[index], b'!' | b'-') && bytes.get(index + 1) != Some(&b'=') {
        return unary_operand_end(bytes, index + 1);
    }
    index = match bytes[index] {
        b'\'' | b'"' => quoted_end(bytes, index),
        b'(' | b'[' | b'{' => grouped_end(bytes, index),
        _ => {
            while index < bytes.len()
                && !bytes[index].is_ascii_whitespace()
                && !matches!(
                    bytes[index],
                    b'!' | b'&'
                        | b'|'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'/'
                        | b'%'
                        | b'<'
                        | b'>'
                        | b'='
                        | b'?'
                        | b':'
                        | b','
                        | b')'
                        | b']'
                        | b'}'
                        | b'('
                        | b'['
                )
            {
                index += 1;
            }
            index
        }
    };
    loop {
        let next = whitespace_end(bytes, index);
        if next >= bytes.len() {
            break;
        }
        match bytes[next] {
            b'(' | b'[' => index = grouped_end(bytes, next),
            _ => break,
        }
    }
    index
}

fn expand_negation_runs(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            let end = quoted_end(bytes, index);
            output.push_str(&source[index..end]);
            index = end;
        } else if bytes[index] == b'!' && bytes.get(index + 1) != Some(&b'=') {
            let mut count = 0;
            let mut cursor = index;
            loop {
                count += 1;
                cursor += 1;
                let next = whitespace_end(bytes, cursor);
                if bytes.get(next) == Some(&b'!') && bytes.get(next + 1) != Some(&b'=') {
                    cursor = next;
                } else {
                    break;
                }
            }
            if count > 1 {
                let end = unary_operand_end(bytes, cursor);
                for _ in 0..count {
                    output.push_str("!(");
                }
                output.push_str(&expand_negation_runs(&source[cursor..end]));
                for _ in 0..count {
                    output.push(')');
                }
                index = end;
            } else {
                output.push('!');
                index += 1;
            }
        } else {
            let character = source[index..].chars().next().expect("valid UTF-8");
            output.push(character);
            index += character.len_utf8();
        }
    }
    output
}

struct Meter {
    remaining: usize,
    spent: usize,
}

impl Meter {
    fn charge(&mut self, units: usize) -> EvalResult<()> {
        if units > self.remaining {
            return Err(InspectionEvaluationError::Limit);
        }
        self.remaining -= units;
        self.spent += units;
        Ok(())
    }
}

pub(crate) fn safe_evaluate(
    source: &str,
    bindings: &BTreeMap<String, Value>,
    maximum_steps: usize,
    snapshot_units: usize,
) -> EvalResult<(bool, usize)> {
    if source.len() > 4096 || snapshot_units > 65536 {
        return Err(InspectionEvaluationError::Limit);
    }
    let ast = Parser::new()
        .parse(source)
        .map_err(|_| InspectionEvaluationError::Guard)?;
    let folded_unaries = source_unary_count(source).saturating_sub(parsed_unary_count(&ast));
    let unfolded_nodes = node_count(&ast) + folded_unaries;
    if unfolded_nodes > 1024 {
        return Err(InspectionEvaluationError::Limit);
    }
    #[cfg(determa_repository_conformance)]
    OBSERVED_GUARDS.with(|counter| counter.set(counter.get() + 1));
    if folded_unaries > 128 {
        let trimmed = source.trim();
        let prefix = trimmed.bytes().take_while(|byte| *byte == b'!').count();
        let literal = trimmed[prefix..].trim();
        if prefix > 128 && matches!(literal, "true" | "false") {
            let spent = 1 + 2 * prefix;
            if spent > maximum_steps {
                return Err(InspectionEvaluationError::Limit);
            }
            return Ok(((literal == "true") == (prefix % 2 == 0), spent));
        }
    }
    let expanded = expand_negation_runs(source);
    let ast = Parser::new()
        .parse(&expanded)
        .map_err(|_| InspectionEvaluationError::Guard)?;
    let mut meter = Meter {
        remaining: maximum_steps,
        spent: 0,
    };
    let value = evaluate(&ast, bindings, &mut meter)?;
    if let Value::Bool(value) = value {
        Ok((value, meter.spent))
    } else {
        Err(InspectionEvaluationError::Guard)
    }
}

fn evaluate(
    expression: &IdedExpr,
    bindings: &BTreeMap<String, Value>,
    meter: &mut Meter,
) -> EvalResult<Value> {
    meter.charge(1)?;
    match &expression.expr {
        Expr::Literal(value) => match value {
            Val::Null => Ok(Value::Null),
            Val::Boolean(value) => Ok(Value::Bool(*value)),
            Val::Int(value) => Ok(Value::Int(*value)),
            Val::Double(value) if value.is_finite() => Ok(Value::Float(*value)),
            Val::String(value) => {
                meter.charge(scalars(value))?;
                Ok(Value::String(value.clone()))
            }
            _ => Err(InspectionEvaluationError::Guard),
        },
        Expr::Ident(name) => bindings
            .get(name)
            .cloned()
            .ok_or(InspectionEvaluationError::Guard),
        Expr::List(list) => {
            let values = list
                .elements
                .iter()
                .map(|item| evaluate(item, bindings, meter))
                .collect::<EvalResult<Vec<_>>>()?;
            let result = Value::List(values);
            meter.charge(value_units(&result))?;
            Ok(result)
        }
        Expr::Map(map) => {
            let mut values = BTreeMap::new();
            for entry in &map.entries {
                let EntryExpr::MapEntry(entry) = &entry.expr else {
                    return Err(InspectionEvaluationError::Guard);
                };
                let Expr::Literal(Val::String(key)) = &entry.key.expr else {
                    return Err(InspectionEvaluationError::Guard);
                };
                meter.charge(1 + scalars(key))?;
                values.insert(key.clone(), evaluate(&entry.value, bindings, meter)?);
            }
            let result = Value::Map(values);
            meter.charge(value_units(&result))?;
            Ok(result)
        }
        Expr::Select(select) => {
            let base = evaluate(&select.operand, bindings, meter)?;
            let Value::Map(values) = base else {
                return Err(InspectionEvaluationError::Guard);
            };
            let cost = if typed_record(&select.operand) {
                1 + scalars(&select.field)
            } else {
                map_lookup_cost(&values, &select.field)
            };
            meter.charge(cost)?;
            if select.test {
                Ok(Value::Bool(values.contains_key(&select.field)))
            } else {
                values
                    .get(&select.field)
                    .cloned()
                    .ok_or(InspectionEvaluationError::Guard)
            }
        }
        Expr::Call(call) if call.target.is_none() => {
            evaluate_call(&call.func_name, &call.args, bindings, meter)
        }
        _ => Err(InspectionEvaluationError::Guard),
    }
}

fn typed_record(expression: &IdedExpr) -> bool {
    match &expression.expr {
        Expr::Ident(name) => name == "event" || name == "owner",
        Expr::Select(select) => matches!(&select.operand.expr, Expr::Ident(name)
            if (name == "event" && select.field == "payload")
                || (name == "owner" && select.field == "variables")),
        _ => false,
    }
}

fn evaluate_call(
    name: &str,
    args: &[IdedExpr],
    bindings: &BTreeMap<String, Value>,
    meter: &mut Meter,
) -> EvalResult<Value> {
    match (name, args) {
        (operators::CONDITIONAL, [condition, yes, no]) => {
            match evaluate(condition, bindings, meter)? {
                Value::Bool(true) => evaluate(yes, bindings, meter),
                Value::Bool(false) => evaluate(no, bindings, meter),
                _ => Err(InspectionEvaluationError::Guard),
            }
        }
        (operators::LOGICAL_AND | operators::LOGICAL_OR, [left, right]) => {
            let left = evaluate(left, bindings, meter);
            if left == Err(InspectionEvaluationError::Limit) {
                return left;
            }
            let right = evaluate(right, bindings, meter);
            if right == Err(InspectionEvaluationError::Limit) {
                return right;
            }
            meter.charge(1)?;
            match (name, left, right) {
                (operators::LOGICAL_AND, Ok(Value::Bool(false)), _)
                | (operators::LOGICAL_AND, _, Ok(Value::Bool(false))) => Ok(Value::Bool(false)),
                (operators::LOGICAL_OR, Ok(Value::Bool(true)), _)
                | (operators::LOGICAL_OR, _, Ok(Value::Bool(true))) => Ok(Value::Bool(true)),
                (operators::LOGICAL_AND, Ok(Value::Bool(true)), Ok(Value::Bool(value)))
                | (operators::LOGICAL_OR, Ok(Value::Bool(false)), Ok(Value::Bool(value))) => {
                    Ok(Value::Bool(value))
                }
                _ => Err(InspectionEvaluationError::Guard),
            }
        }
        (operators::LOGICAL_NOT, [operand]) => {
            let value = evaluate(operand, bindings, meter)?;
            meter.charge(1)?;
            if let Value::Bool(value) = value {
                Ok(Value::Bool(!value))
            } else {
                Err(InspectionEvaluationError::Guard)
            }
        }
        (operators::NEGATE, [operand]) => {
            let value = evaluate(operand, bindings, meter)?;
            meter.charge(1)?;
            match value {
                Value::Int(value) => value
                    .checked_neg()
                    .map(Value::Int)
                    .ok_or(InspectionEvaluationError::Guard),
                Value::Float(value) => finite(-value).map(Value::Float),
                _ => Err(InspectionEvaluationError::Guard),
            }
        }
        (operators::INDEX, [container, index]) => {
            let container = evaluate(container, bindings, meter)?;
            let index = evaluate(index, bindings, meter)?;
            match (container, index) {
                (Value::List(values), Value::Int(index)) => {
                    meter.charge(1)?;
                    usize::try_from(index)
                        .ok()
                        .and_then(|index| values.get(index).cloned())
                        .ok_or(InspectionEvaluationError::Guard)
                }
                (Value::Map(values), Value::String(key)) => {
                    meter.charge(map_lookup_cost(&values, &key))?;
                    values
                        .get(&key)
                        .cloned()
                        .ok_or(InspectionEvaluationError::Guard)
                }
                _ => Err(InspectionEvaluationError::Guard),
            }
        }
        ("size", [operand]) => {
            let value = evaluate(operand, bindings, meter)?;
            let (cost, size) = match value {
                Value::String(value) => (scalars(&value), scalars(&value)),
                Value::List(value) => (1, value.len()),
                Value::Map(value) => (value_units(&Value::Map(value.clone())), value.len()),
                _ => return Err(InspectionEvaluationError::Guard),
            };
            meter.charge(cost)?;
            i64::try_from(size)
                .map(Value::Int)
                .map_err(|_| InspectionEvaluationError::Guard)
        }
        ("string", [operand]) => {
            let value = evaluate(operand, bindings, meter)?;
            let converted = match &value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Int(value) => value.to_string(),
                Value::Float(value) if value.is_finite() => {
                    if *value == 0.0 {
                        "0".to_string()
                    } else {
                        ryu_js::Buffer::new().format(*value).to_string()
                    }
                }
                _ => return Err(InspectionEvaluationError::Guard),
            };
            meter.charge(scalars(&converted))?;
            Ok(Value::String(converted))
        }
        ("int", [operand]) => {
            let value = evaluate(operand, bindings, meter)?;
            meter.charge(1)?;
            match value {
                Value::Float(value)
                    if value.is_finite()
                        && value >= i64::MIN as f64
                        && value < 9_223_372_036_854_775_808.0 =>
                {
                    Ok(Value::Int(value.trunc() as i64))
                }
                _ => Err(InspectionEvaluationError::Guard),
            }
        }
        ("double", [operand]) => {
            let value = evaluate(operand, bindings, meter)?;
            meter.charge(1)?;
            match value {
                Value::Int(value) => Ok(Value::Float(value as f64)),
                _ => Err(InspectionEvaluationError::Guard),
            }
        }
        (operators::EQUALS | operators::NOT_EQUALS, [left, right]) => {
            let left = evaluate(left, bindings, meter)?;
            let right = evaluate(right, bindings, meter)?;
            meter.charge(if matches!(left, Value::List(_) | Value::Map(_)) {
                value_units(&left) + value_units(&right)
            } else if let (Value::String(left), Value::String(right)) = (&left, &right) {
                scalars(left) + scalars(right)
            } else {
                1
            })?;
            let equal = left == right;
            Ok(Value::Bool(if name == operators::EQUALS {
                equal
            } else {
                !equal
            }))
        }
        (
            operators::GREATER
            | operators::GREATER_EQUALS
            | operators::LESS
            | operators::LESS_EQUALS,
            [left, right],
        ) => {
            let left = evaluate(left, bindings, meter)?;
            let right = evaluate(right, bindings, meter)?;
            meter.charge(
                if let (Value::String(left), Value::String(right)) = (&left, &right) {
                    scalars(left) + scalars(right)
                } else {
                    1
                },
            )?;
            let order = match (left, right) {
                (Value::Int(left), Value::Int(right)) => left.cmp(&right),
                (Value::Float(left), Value::Float(right)) => left
                    .partial_cmp(&right)
                    .ok_or(InspectionEvaluationError::Guard)?,
                (Value::String(left), Value::String(right)) => left.chars().cmp(right.chars()),
                _ => return Err(InspectionEvaluationError::Guard),
            };
            Ok(Value::Bool(match name {
                operators::GREATER => order.is_gt(),
                operators::GREATER_EQUALS => order.is_ge(),
                operators::LESS => order.is_lt(),
                _ => order.is_le(),
            }))
        }
        (operators::IN, [needle, haystack]) => {
            let needle = evaluate(needle, bindings, meter)?;
            let haystack = evaluate(haystack, bindings, meter)?;
            match haystack {
                Value::List(values) => {
                    meter
                        .charge(value_units(&Value::List(values.clone())) + value_units(&needle))?;
                    Ok(Value::Bool(values.iter().any(|item| item == &needle)))
                }
                Value::Map(values) => {
                    let Value::String(key) = needle else {
                        return Err(InspectionEvaluationError::Guard);
                    };
                    meter.charge(map_lookup_cost(&values, &key))?;
                    Ok(Value::Bool(values.contains_key(&key)))
                }
                _ => Err(InspectionEvaluationError::Guard),
            }
        }
        (
            operators::ADD
            | operators::SUBSTRACT
            | operators::MULTIPLY
            | operators::DIVIDE
            | operators::MODULO,
            [left, right],
        ) => {
            let left = evaluate(left, bindings, meter)?;
            let right = evaluate(right, bindings, meter)?;
            let cost = match (&left, &right) {
                (Value::String(left), Value::String(right)) if name == operators::ADD => {
                    scalars(left) + scalars(right) + scalars(&(left.clone() + right))
                }
                (Value::List(left), Value::List(right)) if name == operators::ADD => {
                    left.len() + right.len() + left.len() + right.len()
                }
                _ => 1,
            };
            meter.charge(cost)?;
            arithmetic(name, left, right)
        }
        _ => Err(InspectionEvaluationError::Guard),
    }
}

fn finite(value: f64) -> EvalResult<f64> {
    if value.is_finite() {
        Ok(if value == 0.0 { 0.0 } else { value })
    } else {
        Err(InspectionEvaluationError::Guard)
    }
}

fn arithmetic(name: &str, left: Value, right: Value) -> EvalResult<Value> {
    match (left, right) {
        (Value::Int(left), Value::Int(right)) => {
            let value = match name {
                operators::ADD => left.checked_add(right),
                operators::SUBSTRACT => left.checked_sub(right),
                operators::MULTIPLY => left.checked_mul(right),
                operators::DIVIDE => left.checked_div(right),
                operators::MODULO => left.checked_rem(right),
                _ => None,
            };
            value
                .map(Value::Int)
                .ok_or(InspectionEvaluationError::Guard)
        }
        (Value::Float(left), Value::Float(right)) => {
            let value = match name {
                operators::ADD => left + right,
                operators::SUBSTRACT => left - right,
                operators::MULTIPLY => left * right,
                operators::DIVIDE => left / right,
                operators::MODULO => left % right,
                _ => return Err(InspectionEvaluationError::Guard),
            };
            finite(value).map(Value::Float)
        }
        (Value::String(left), Value::String(right)) if name == operators::ADD => {
            Ok(Value::String(left + &right))
        }
        (Value::List(mut left), Value::List(right)) if name == operators::ADD => {
            left.extend(right);
            Ok(Value::List(left))
        }
        _ => Err(InspectionEvaluationError::Guard),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(source: &str, budget: usize) -> EvalResult<(bool, usize)> {
        safe_evaluate(source, &BTreeMap::new(), budget, 0)
    }

    #[test]
    fn portable_fuel_boundaries_charge_before_returning() {
        for (source, budget, expected) in [
            ("true", 1, true),
            ("!true", 3, false),
            ("false && true", 4, false),
            ("!!true", 5, true),
            ("!!!true", 7, false),
            ("! !true", 5, true),
            ("!!true && false", 8, false),
            ("size(\"ab\") == 2", 9, true),
            ("size({\"é\":1}) == 1", 14, true),
        ] {
            assert_eq!(evaluate(source, budget), Ok((expected, budget)), "{source}");
            assert_eq!(
                evaluate(source, budget - 1),
                Err(InspectionEvaluationError::Limit),
                "{source}"
            );
        }
    }

    #[test]
    fn integer_division_is_exact_and_errors_have_no_boolean_result() {
        for source in [
            "-3 / 2 == -1",
            "-3 % 2 == -1",
            "3 / -2 == -1",
            "3 % -2 == 1",
            "9223372036854775807 / 3 == 3074457345618258602",
            "9223372036854775807 % 3 == 1",
        ] {
            assert_eq!(
                evaluate(source, 100),
                Ok((true, evaluate(source, 100).unwrap().1)),
                "{source}"
            );
        }
        assert_eq!(
            evaluate("1 / 0 == 0", 4),
            Err(InspectionEvaluationError::Limit)
        );
        assert_eq!(
            evaluate("1 / 0 == 0", 5),
            Err(InspectionEvaluationError::Guard)
        );
        assert_eq!(
            evaluate("-9223372036854775808 / -1 == 0", 100),
            Err(InspectionEvaluationError::Guard)
        );
    }

    #[test]
    fn source_ast_snapshot_and_unicode_caps_are_independent() {
        assert_eq!(
            evaluate(&format!("{}true", "!".repeat(1024)), 1_000_000),
            Err(InspectionEvaluationError::Limit)
        );
        assert_eq!(
            safe_evaluate("true", &BTreeMap::new(), 1, 65537),
            Err(InspectionEvaluationError::Limit)
        );
        assert!(evaluate("size(\"é😀\") == 2", 100).unwrap().0);
    }
}
