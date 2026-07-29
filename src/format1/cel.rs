use super::compile::SemanticError;
use super::source::LoadErrorCode;
use crate::value::Value;
use cel_parser::ast::operators;
use cel_parser::ast::{EntryExpr, Expr, IdedExpr};
use cel_parser::reference::Val;
use cel_parser::Parser;
use std::cmp::Ordering;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct Environment {
    pub values: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct EvaluationError(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CelType {
    Null,
    Bool,
    Int,
    Double,
    String,
    List(Box<CelType>),
    Map(Box<CelType>),
    Record(BTreeMap<String, RecordField>),
    InstanceReference(Option<String>),
    Dyn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordField {
    pub value_type: CelType,
    pub optional: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TypeEnvironment {
    pub values: BTreeMap<String, CelType>,
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub(crate) fn declared_type(value_type: &str, machine_id: Option<&str>) -> CelType {
    match value_type {
        "bool" => CelType::Bool,
        "int" => CelType::Int,
        "float" => CelType::Double,
        "string" => CelType::String,
        "list" => CelType::List(Box::new(CelType::Dyn)),
        "map" => CelType::Map(Box::new(CelType::Dyn)),
        "instance_reference" => CelType::InstanceReference(machine_id.map(str::to_string)),
        _ => CelType::Dyn,
    }
}

pub(crate) fn value_type(value: &Value) -> CelType {
    match value {
        Value::Null => CelType::Null,
        Value::Bool(_) => CelType::Bool,
        Value::Int(_) => CelType::Int,
        Value::Float(_) => CelType::Double,
        Value::String(_) => CelType::String,
        Value::List(values) => CelType::List(Box::new(common_type(values.iter().map(value_type)))),
        Value::Map(values) => CelType::Map(Box::new(common_type(values.values().map(value_type)))),
        Value::InstanceReference(reference) => {
            CelType::InstanceReference(Some(reference.machine_id.clone()))
        }
    }
}

fn common_type(mut types: impl Iterator<Item = CelType>) -> CelType {
    let Some(first) = types.next() else {
        return CelType::Dyn;
    };
    if types.all(|value| value == first) {
        first
    } else {
        CelType::Dyn
    }
}

pub(crate) fn check(
    expression: &str,
    pointer: &str,
    environment: &TypeEnvironment,
    expected: &CelType,
) -> Result<CelType, SemanticError> {
    let inferred = infer_expression(expression, pointer, environment)?;
    if is_assignable(&inferred, expected) {
        Ok(inferred)
    } else {
        Err(type_error(
            pointer,
            format!("expression type {inferred:?} is not assignable to {expected:?}"),
        ))
    }
}

pub(crate) fn infer_expression(
    expression: &str,
    pointer: &str,
    environment: &TypeEnvironment,
) -> Result<CelType, SemanticError> {
    let expression = Parser::new()
        .parse(expression)
        .map_err(|error| SemanticError {
            code: LoadErrorCode::SemanticValidation,
            path: pointer.to_string(),
            message: format!("CEL parse error: {error}"),
        })?;
    infer(&expression, environment, pointer)
}

fn infer(
    expression: &IdedExpr,
    environment: &TypeEnvironment,
    pointer: &str,
) -> Result<CelType, SemanticError> {
    match &expression.expr {
        Expr::Unspecified => Err(profile_error(pointer, "unspecified CEL expression")),
        Expr::Literal(value) => match value {
            Val::Null => Ok(CelType::Null),
            Val::Boolean(_) => Ok(CelType::Bool),
            Val::Int(_) => Ok(CelType::Int),
            Val::Double(value) if value.is_finite() => Ok(CelType::Double),
            Val::String(_) => Ok(CelType::String),
            Val::UInt(_) | Val::Bytes(_) | Val::Double(_) => Err(profile_error(
                pointer,
                "literal is outside the portable profile",
            )),
        },
        Expr::Ident(name) => environment
            .values
            .get(name)
            .cloned()
            .ok_or_else(|| type_error(pointer, format!("unknown CEL activation name {name:?}"))),
        Expr::List(list) => Ok(CelType::List(Box::new(common_type(
            list.elements
                .iter()
                .map(|value| infer(value, environment, pointer))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter(),
        )))),
        Expr::Map(map) => {
            let mut value_types = Vec::new();
            let mut keys = std::collections::BTreeSet::new();
            for entry in &map.entries {
                let EntryExpr::MapEntry(entry) = &entry.expr else {
                    return Err(profile_error(
                        pointer,
                        "object construction is outside the portable profile",
                    ));
                };
                if entry.optional {
                    return Err(profile_error(
                        pointer,
                        "optional map entries are outside the portable profile",
                    ));
                }
                let Expr::Literal(Val::String(key)) = &entry.key.expr else {
                    return Err(profile_error(
                        pointer,
                        "portable CEL maps require literal string keys",
                    ));
                };
                if !keys.insert(key) {
                    return Err(type_error(
                        pointer,
                        format!("duplicate CEL map key {key:?}"),
                    ));
                }
                let value_type = infer(&entry.value, environment, pointer)?;
                value_types.push(value_type.clone());
            }
            Ok(CelType::Map(Box::new(common_type(value_types.into_iter()))))
        }
        Expr::Struct(_) => Err(profile_error(
            pointer,
            "object construction is outside the portable profile",
        )),
        Expr::Comprehension(_) => Err(profile_error(
            pointer,
            "comprehensions are outside the portable profile",
        )),
        Expr::Select(select) => {
            let operand = infer(&select.operand, environment, pointer)?;
            if select.test {
                return match operand {
                    CelType::Map(_) => Ok(CelType::Bool),
                    CelType::Record(fields)
                        if is_event_payload_access(&select.operand)
                            && fields.contains_key(&select.field) =>
                    {
                        Ok(CelType::Bool)
                    }
                    _ => Err(profile_error(
                        pointer,
                        "has() is available only for maps and declared event payload fields",
                    )),
                };
            }
            match operand {
                CelType::Record(fields) => fields
                    .get(&select.field)
                    .map(|field| field.value_type.clone())
                    .ok_or_else(|| {
                        profile_error(
                            pointer,
                            format!(
                                "record field {:?} is outside the portable profile",
                                select.field
                            ),
                        )
                    }),
                CelType::Map(value_type) => Ok(*value_type),
                CelType::InstanceReference(_) => Err(profile_error(
                    pointer,
                    "instance_reference values are nominal and cannot be inspected",
                )),
                _ => Err(type_error(
                    pointer,
                    "field selection requires a record or map",
                )),
            }
        }
        Expr::Call(call) => {
            if call.target.is_some() {
                return Err(profile_error(
                    pointer,
                    "receiver methods are outside the portable profile",
                ));
            }
            let arguments = call
                .args
                .iter()
                .map(|argument| infer(argument, environment, pointer))
                .collect::<Result<Vec<_>, _>>()?;
            infer_call(&call.func_name, &arguments, pointer)
        }
    }
}

fn is_event_payload_access(expression: &IdedExpr) -> bool {
    let Expr::Select(payload) = &expression.expr else {
        return false;
    };
    payload.field == "payload"
        && !payload.test
        && matches!(&payload.operand.expr, Expr::Ident(name) if name == "event")
}

fn infer_call(name: &str, arguments: &[CelType], pointer: &str) -> Result<CelType, SemanticError> {
    match (name, arguments) {
        (operators::CONDITIONAL, [CelType::Bool, selected, unselected]) => {
            merge_conditional(selected, unselected)
                .ok_or_else(|| type_error(pointer, "conditional branches have incompatible types"))
        }
        (operators::LOGICAL_AND | operators::LOGICAL_OR, [CelType::Bool, CelType::Bool])
        | (operators::LOGICAL_NOT, [CelType::Bool]) => Ok(CelType::Bool),
        (operators::NEGATE, [CelType::Int]) => Ok(CelType::Int),
        (operators::NEGATE, [CelType::Double]) => Ok(CelType::Double),
        (
            operators::ADD
            | operators::SUBSTRACT
            | operators::MULTIPLY
            | operators::DIVIDE
            | operators::MODULO,
            [CelType::Int, CelType::Int],
        ) => Ok(CelType::Int),
        (
            operators::ADD
            | operators::SUBSTRACT
            | operators::MULTIPLY
            | operators::DIVIDE
            | operators::MODULO,
            [CelType::Double, CelType::Double],
        ) => Ok(CelType::Double),
        (operators::ADD, [CelType::String, CelType::String]) => Ok(CelType::String),
        (operators::ADD, [CelType::List(left), CelType::List(right)]) => {
            Ok(CelType::List(Box::new(merge_dynamic(left, right))))
        }
        (
            operators::EQUALS | operators::NOT_EQUALS,
            [CelType::InstanceReference(left), CelType::InstanceReference(right)],
        ) if nominally_compatible(left.as_deref(), right.as_deref()) => Ok(CelType::Bool),
        (
            operators::EQUALS | operators::NOT_EQUALS,
            [CelType::InstanceReference(_), CelType::Null]
            | [CelType::Null, CelType::InstanceReference(_)],
        ) => Ok(CelType::Bool),
        (operators::EQUALS | operators::NOT_EQUALS, [left, right])
            if equality_compatible(left, right) =>
        {
            Ok(CelType::Bool)
        }
        (
            operators::GREATER
            | operators::GREATER_EQUALS
            | operators::LESS
            | operators::LESS_EQUALS,
            [left, right],
        ) if left == right && matches!(left, CelType::Int | CelType::Double | CelType::String) => {
            Ok(CelType::Bool)
        }
        (operators::IN, [_, CelType::List(_)]) => Ok(CelType::Bool),
        (operators::IN, [CelType::String, CelType::Map(_)])
        | (operators::IN, [CelType::String, CelType::Record(_)]) => Ok(CelType::Bool),
        (operators::INDEX, [CelType::List(element), CelType::Int]) => Ok((**element).clone()),
        (operators::INDEX, [CelType::Map(value), CelType::String]) => Ok((**value).clone()),
        (operators::INDEX, [CelType::Record(fields), CelType::String]) => Ok(common_type(
            fields.values().map(|field| field.value_type.clone()),
        )),
        ("size", [CelType::String | CelType::List(_) | CelType::Map(_) | CelType::Record(_)]) => {
            Ok(CelType::Int)
        }
        ("double", [CelType::Int]) => Ok(CelType::Double),
        ("int", [CelType::Double]) => Ok(CelType::Int),
        ("string", [CelType::Bool | CelType::Int | CelType::Double | CelType::String]) => {
            Ok(CelType::String)
        }
        _ => Err(profile_error(
            pointer,
            format!("unavailable portable CEL symbol or overload {name:?}"),
        )),
    }
}

fn nominally_compatible(left: Option<&str>, right: Option<&str>) -> bool {
    left.is_none() || right.is_none() || left == right
}

fn equality_compatible(left: &CelType, right: &CelType) -> bool {
    match (left, right) {
        (CelType::List(_), CelType::List(_)) | (CelType::Map(_), CelType::Map(_)) => true,
        (CelType::Record(_), CelType::Record(_))
        | (CelType::Map(_), CelType::Record(_))
        | (CelType::Record(_), CelType::Map(_)) => true,
        _ => left == right && !matches!(left, CelType::Dyn),
    }
}

fn merge_dynamic(left: &CelType, right: &CelType) -> CelType {
    if left == right {
        left.clone()
    } else {
        CelType::Dyn
    }
}

fn merge_conditional(left: &CelType, right: &CelType) -> Option<CelType> {
    if left == right {
        Some(left.clone())
    } else {
        match (left, right) {
            (CelType::InstanceReference(_), CelType::Null) => Some(left.clone()),
            (CelType::Null, CelType::InstanceReference(_)) => Some(right.clone()),
            _ => None,
        }
    }
}

pub(crate) fn is_assignable(actual: &CelType, expected: &CelType) -> bool {
    match (actual, expected) {
        (CelType::Int, CelType::Double) => true,
        (CelType::InstanceReference(actual), CelType::InstanceReference(expected)) => {
            nominally_compatible(actual.as_deref(), expected.as_deref())
        }
        (CelType::Null, CelType::InstanceReference(_)) => true,
        (CelType::List(actual), CelType::List(expected))
        | (CelType::Map(actual), CelType::Map(expected)) => {
            matches!(**expected, CelType::Dyn) || is_assignable(actual, expected)
        }
        (CelType::Record(_), CelType::Map(expected)) => matches!(**expected, CelType::Dyn),
        _ => actual == expected,
    }
}

fn profile_error(pointer: &str, message: impl Into<String>) -> SemanticError {
    SemanticError {
        code: LoadErrorCode::CelProfileError,
        path: pointer.to_string(),
        message: message.into(),
    }
}

fn type_error(pointer: &str, message: impl Into<String>) -> SemanticError {
    SemanticError {
        code: LoadErrorCode::SemanticValidation,
        path: pointer.to_string(),
        message: message.into(),
    }
}

pub fn evaluate(expression: &str, environment: &Environment) -> Result<Value, EvaluationError> {
    let expression = Parser::new()
        .parse(expression)
        .map_err(|error| EvaluationError(format!("CEL parse error: {error}")))?;
    let mut meter = EvaluationMeter {
        steps: 0,
        maximum: usize::MAX,
    };
    evaluate_ast(&expression, environment, &mut meter)
}

pub(crate) fn migration_expression_info(expression: &str) -> Result<usize, EvaluationError> {
    let expression = Parser::new()
        .parse(expression)
        .map_err(|error| EvaluationError(format!("CEL parse error: {error}")))?;
    Ok(ast_nodes(&expression))
}

pub(crate) fn evaluate_migration(
    expression: &str,
    environment: &Environment,
    maximum_steps: usize,
) -> Result<(Value, usize), EvaluationError> {
    let expression = Parser::new()
        .parse(expression)
        .map_err(|error| EvaluationError(format!("CEL parse error: {error}")))?;
    let mut meter = EvaluationMeter {
        steps: 0,
        maximum: maximum_steps,
    };
    let value = evaluate_ast(&expression, environment, &mut meter)?;
    Ok((value, meter.steps))
}

struct EvaluationMeter {
    steps: usize,
    maximum: usize,
}

impl EvaluationMeter {
    fn enter(&mut self) -> Result<(), EvaluationError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.maximum {
            Err(EvaluationError(
                "migration CEL evaluation step limit exceeded".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

fn ast_nodes(expression: &IdedExpr) -> usize {
    1 + match &expression.expr {
        Expr::Call(call) => {
            call.target.as_deref().map_or(0, ast_nodes)
                + call.args.iter().map(ast_nodes).sum::<usize>()
        }
        Expr::Comprehension(comprehension) => {
            ast_nodes(&comprehension.iter_range)
                + ast_nodes(&comprehension.accu_init)
                + ast_nodes(&comprehension.loop_cond)
                + ast_nodes(&comprehension.loop_step)
                + ast_nodes(&comprehension.result)
        }
        Expr::List(list) => list.elements.iter().map(ast_nodes).sum(),
        Expr::Map(map) => map
            .entries
            .iter()
            .map(|entry| {
                1 + match &entry.expr {
                    EntryExpr::MapEntry(entry) => ast_nodes(&entry.key) + ast_nodes(&entry.value),
                    EntryExpr::StructField(entry) => ast_nodes(&entry.value),
                }
            })
            .sum::<usize>(),
        Expr::Select(select) => ast_nodes(&select.operand),
        Expr::Struct(structure) => structure
            .entries
            .iter()
            .map(|entry| {
                1 + match &entry.expr {
                    EntryExpr::MapEntry(entry) => ast_nodes(&entry.key) + ast_nodes(&entry.value),
                    EntryExpr::StructField(entry) => ast_nodes(&entry.value),
                }
            })
            .sum::<usize>(),
        Expr::Unspecified | Expr::Ident(_) | Expr::Literal(_) => 0,
    }
}

pub fn evaluate_boolean(
    expression: &str,
    environment: &Environment,
) -> Result<bool, EvaluationError> {
    match evaluate(expression, environment)? {
        Value::Bool(value) => Ok(value),
        value => Err(EvaluationError(format!(
            "guard returned {}, expected bool",
            value.type_name()
        ))),
    }
}

fn evaluate_ast(
    expression: &IdedExpr,
    environment: &Environment,
    meter: &mut EvaluationMeter,
) -> Result<Value, EvaluationError> {
    meter.enter()?;
    match &expression.expr {
        Expr::Literal(value) => match value {
            Val::Null => Ok(Value::Null),
            Val::Boolean(value) => Ok(Value::Bool(*value)),
            Val::Int(value) => Ok(Value::Int(*value)),
            Val::Double(value) => finite_float(*value),
            Val::String(value) => Ok(Value::String(value.clone())),
            Val::UInt(_) | Val::Bytes(_) => profile_runtime_error(),
        },
        Expr::Ident(name) => environment
            .values
            .get(name)
            .cloned()
            .ok_or_else(|| EvaluationError(format!("unknown activation name {name:?}"))),
        Expr::List(list) => list
            .elements
            .iter()
            .map(|value| evaluate_ast(value, environment, meter))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List),
        Expr::Map(map) => {
            let mut output = BTreeMap::new();
            for entry in &map.entries {
                let EntryExpr::MapEntry(entry) = &entry.expr else {
                    return profile_runtime_error();
                };
                let Expr::Literal(Val::String(key)) = &entry.key.expr else {
                    return profile_runtime_error();
                };
                output.insert(key.clone(), evaluate_ast(&entry.value, environment, meter)?);
            }
            Ok(Value::Map(output))
        }
        Expr::Select(select) => {
            let operand = evaluate_ast(&select.operand, environment, meter)?;
            let Value::Map(values) = operand else {
                return Err(EvaluationError(
                    "field selection requires a map or record".to_string(),
                ));
            };
            if select.test {
                Ok(Value::Bool(values.contains_key(&select.field)))
            } else {
                values
                    .get(&select.field)
                    .cloned()
                    .ok_or_else(|| EvaluationError(format!("missing field {:?}", select.field)))
            }
        }
        Expr::Call(call) if call.target.is_none() => {
            evaluate_call(&call.func_name, &call.args, environment, meter)
        }
        Expr::Unspecified | Expr::Call(_) | Expr::Comprehension(_) | Expr::Struct(_) => {
            profile_runtime_error()
        }
    }
}

fn evaluate_call(
    name: &str,
    arguments: &[IdedExpr],
    environment: &Environment,
    meter: &mut EvaluationMeter,
) -> Result<Value, EvaluationError> {
    match (name, arguments) {
        (operators::CONDITIONAL, [condition, selected, unselected]) => {
            match evaluate_ast(condition, environment, meter)? {
                Value::Bool(true) => evaluate_ast(selected, environment, meter),
                Value::Bool(false) => evaluate_ast(unselected, environment, meter),
                _ => Err(EvaluationError(
                    "conditional condition must be Boolean".to_string(),
                )),
            }
        }
        (operators::LOGICAL_AND | operators::LOGICAL_OR, [left, right]) => {
            let left = evaluate_ast(left, environment, meter);
            let right = evaluate_ast(right, environment, meter);
            match (name, left, right) {
                (operators::LOGICAL_AND, Ok(Value::Bool(false)), _)
                | (operators::LOGICAL_AND, _, Ok(Value::Bool(false))) => Ok(Value::Bool(false)),
                (operators::LOGICAL_AND, Ok(Value::Bool(true)), Ok(Value::Bool(value))) => {
                    Ok(Value::Bool(value))
                }
                (operators::LOGICAL_OR, Ok(Value::Bool(true)), _)
                | (operators::LOGICAL_OR, _, Ok(Value::Bool(true))) => Ok(Value::Bool(true)),
                (operators::LOGICAL_OR, Ok(Value::Bool(false)), Ok(Value::Bool(value))) => {
                    Ok(Value::Bool(value))
                }
                (_, Err(error), _) | (_, _, Err(error)) => Err(error),
                _ => Err(EvaluationError(
                    "logical operands must be Boolean".to_string(),
                )),
            }
        }
        (operators::LOGICAL_NOT, [value]) => match evaluate_ast(value, environment, meter)? {
            Value::Bool(value) => Ok(Value::Bool(!value)),
            _ => Err(EvaluationError("! requires bool".to_string())),
        },
        (operators::NEGATE, [value]) => match evaluate_ast(value, environment, meter)? {
            Value::Int(value) => value
                .checked_neg()
                .map(Value::Int)
                .ok_or_else(|| EvaluationError("integer overflow".to_string())),
            Value::Float(value) => finite_float(-value),
            _ => Err(EvaluationError("- requires a numeric value".to_string())),
        },
        (
            operators::ADD
            | operators::SUBSTRACT
            | operators::MULTIPLY
            | operators::DIVIDE
            | operators::MODULO,
            [left, right],
        ) => evaluate_arithmetic(
            name,
            evaluate_ast(left, environment, meter)?,
            evaluate_ast(right, environment, meter)?,
        ),
        (operators::EQUALS | operators::NOT_EQUALS, [left, right]) => {
            let equal =
                evaluate_ast(left, environment, meter)? == evaluate_ast(right, environment, meter)?;
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
            let ordering = compare_values(
                &evaluate_ast(left, environment, meter)?,
                &evaluate_ast(right, environment, meter)?,
            )?;
            Ok(Value::Bool(match name {
                operators::GREATER => ordering == Ordering::Greater,
                operators::GREATER_EQUALS => ordering != Ordering::Less,
                operators::LESS => ordering == Ordering::Less,
                operators::LESS_EQUALS => ordering != Ordering::Greater,
                _ => unreachable!(),
            }))
        }
        (operators::IN, [needle, haystack]) => {
            let needle = evaluate_ast(needle, environment, meter)?;
            match evaluate_ast(haystack, environment, meter)? {
                Value::List(values) => Ok(Value::Bool(values.contains(&needle))),
                Value::Map(values) => match needle {
                    Value::String(value) => Ok(Value::Bool(values.contains_key(&value))),
                    _ => Err(EvaluationError(
                        "map membership requires string".to_string(),
                    )),
                },
                _ => Err(EvaluationError("in requires list or map".to_string())),
            }
        }
        (operators::INDEX, [container, index]) => {
            let container = evaluate_ast(container, environment, meter)?;
            let index = evaluate_ast(index, environment, meter)?;
            match (container, index) {
                (Value::List(values), Value::Int(index)) => usize::try_from(index)
                    .ok()
                    .and_then(|index| values.get(index).cloned())
                    .ok_or_else(|| EvaluationError("list index is out of range".to_string())),
                (Value::Map(values), Value::String(key)) => values
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| EvaluationError("map key is absent".to_string())),
                _ => Err(EvaluationError("invalid index operation".to_string())),
            }
        }
        ("size", [value]) => match evaluate_ast(value, environment, meter)? {
            Value::String(value) => checked_size(value.chars().count()),
            Value::List(value) => checked_size(value.len()),
            Value::Map(value) => checked_size(value.len()),
            _ => Err(EvaluationError(
                "size requires a string, list, or map".to_string(),
            )),
        },
        ("double", [value]) => match evaluate_ast(value, environment, meter)? {
            Value::Int(value) => finite_float(value as f64),
            _ => profile_runtime_error(),
        },
        ("int", [value]) => match evaluate_ast(value, environment, meter)? {
            Value::Float(value)
                if value.is_finite()
                    && value >= i64::MIN as f64
                    && value < 9_223_372_036_854_775_808.0 =>
            {
                Ok(Value::Int(value.trunc() as i64))
            }
            Value::Float(_) => Err(EvaluationError(
                "double is outside the signed 64-bit conversion domain".to_string(),
            )),
            _ => profile_runtime_error(),
        },
        ("string", [value]) => match evaluate_ast(value, environment, meter)? {
            Value::Bool(value) => Ok(Value::String(value.to_string())),
            Value::Int(value) => Ok(Value::String(value.to_string())),
            Value::Float(value) => Ok(Value::String(canonical_double(value)?)),
            Value::String(value) => Ok(Value::String(value)),
            _ => profile_runtime_error(),
        },
        _ => profile_runtime_error(),
    }
}

fn evaluate_arithmetic(
    operator: &str,
    left: Value,
    right: Value,
) -> Result<Value, EvaluationError> {
    match (left, right) {
        (Value::Int(left), Value::Int(right)) => {
            let value = match operator {
                operators::ADD => left.checked_add(right),
                operators::SUBSTRACT => left.checked_sub(right),
                operators::MULTIPLY => left.checked_mul(right),
                operators::DIVIDE => left.checked_div(right),
                operators::MODULO => left.checked_rem(right),
                _ => None,
            };
            value.map(Value::Int).ok_or_else(|| {
                EvaluationError(
                    if right == 0 && matches!(operator, operators::DIVIDE | operators::MODULO) {
                        "division or remainder by zero".to_string()
                    } else {
                        "integer overflow".to_string()
                    },
                )
            })
        }
        (Value::Float(left), Value::Float(right)) => {
            let value = match operator {
                operators::ADD => left + right,
                operators::SUBSTRACT => left - right,
                operators::MULTIPLY => left * right,
                operators::DIVIDE => left / right,
                operators::MODULO => left % right,
                _ => return profile_runtime_error(),
            };
            finite_float(value)
        }
        (Value::String(mut left), Value::String(right)) if operator == operators::ADD => {
            left.push_str(&right);
            Ok(Value::String(left))
        }
        (Value::List(mut left), Value::List(right)) if operator == operators::ADD => {
            left.extend(right);
            Ok(Value::List(left))
        }
        _ => profile_runtime_error(),
    }
}

fn compare_values(left: &Value, right: &Value) -> Result<Ordering, EvaluationError> {
    match (left, right) {
        (Value::Int(left), Value::Int(right)) => Ok(left.cmp(right)),
        (Value::Float(left), Value::Float(right)) => left
            .partial_cmp(right)
            .ok_or_else(|| EvaluationError("non-finite comparison".to_string())),
        (Value::String(left), Value::String(right)) => Ok(left.chars().cmp(right.chars())),
        _ => profile_runtime_error(),
    }
}

fn checked_size(value: usize) -> Result<Value, EvaluationError> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| EvaluationError("size is outside signed 64-bit range".to_string()))
}

fn finite_float(value: f64) -> Result<Value, EvaluationError> {
    if value.is_finite() {
        Ok(Value::Float(if value == 0.0 { 0.0 } else { value }))
    } else {
        Err(EvaluationError(
            "floating-point result is not finite".to_string(),
        ))
    }
}

fn canonical_double(value: f64) -> Result<String, EvaluationError> {
    if !value.is_finite() {
        return Err(EvaluationError(
            "floating-point value is not finite".to_string(),
        ));
    }
    if value == 0.0 {
        return Ok("0".to_string());
    }
    Ok(ryu_js::Buffer::new().format(value).to_string())
}

fn profile_runtime_error<T>() -> Result<T, EvaluationError> {
    Err(EvaluationError(
        "expression is outside the portable CEL profile".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::InstanceReference;

    #[test]
    fn portable_integer_division_and_remainder() {
        assert_eq!(
            evaluate("-7 / 3", &Environment::default()).unwrap(),
            Value::Int(-2)
        );
        assert_eq!(
            evaluate("-7 % 3", &Environment::default()).unwrap(),
            Value::Int(-1)
        );
    }

    #[test]
    fn strict_guard_type() {
        assert!(evaluate_boolean("1", &Environment::default()).is_err());
    }

    #[test]
    fn ast_checker_accepts_only_declared_symbols_and_overloads() {
        let environment = TypeEnvironment {
            values: BTreeMap::from([
                ("converted".to_string(), CelType::Int),
                (
                    "worker".to_string(),
                    CelType::InstanceReference(Some("worker".to_string())),
                ),
            ]),
        };
        assert_eq!(
            check("int(1.5)", "/assign", &environment, &CelType::Int).unwrap(),
            CelType::Int
        );
        assert_eq!(
            check(
                "missing_symbol == 1",
                "/guard",
                &environment,
                &CelType::Bool
            )
            .unwrap_err()
            .code,
            LoadErrorCode::SemanticValidation
        );
        assert_eq!(
            check(
                "\"abc\".contains(\"a\")",
                "/guard",
                &environment,
                &CelType::Bool
            )
            .unwrap_err()
            .code,
            LoadErrorCode::CelProfileError
        );
        assert_eq!(
            check("2 != 3.0", "/guard", &environment, &CelType::Bool)
                .unwrap_err()
                .code,
            LoadErrorCode::CelProfileError
        );
        assert_eq!(
            check(
                "worker.instance_id == \"hidden\"",
                "/guard",
                &environment,
                &CelType::Bool
            )
            .unwrap_err()
            .code,
            LoadErrorCode::CelProfileError
        );
    }

    #[test]
    fn portable_conversion_vectors_are_exact() {
        for (expression, expected) in [
            ("string(1.0)", Value::String("1".to_string())),
            ("string(-0.0)", Value::String("0".to_string())),
            ("string(1e-7)", Value::String("1e-7".to_string())),
            ("int(1.9)", Value::Int(1)),
            ("int(-1.9)", Value::Int(-1)),
            ("double(9007199254740993)", Value::Float(9007199254740992.0)),
        ] {
            assert_eq!(
                evaluate(expression, &Environment::default()).unwrap(),
                expected
            );
        }
        assert!(evaluate("int(1e20)", &Environment::default()).is_err());
        assert!(evaluate("1.0 / 0.0", &Environment::default()).is_err());
        assert!(evaluate("9223372036854775807 + 1", &Environment::default()).is_err());
    }

    #[test]
    fn unicode_size_order_and_nominal_equality_are_portable() {
        assert_eq!(
            evaluate("size(\"e\u{301}\")", &Environment::default()).unwrap(),
            Value::Int(2)
        );
        assert_eq!(
            evaluate("\"a\" < \"é\"", &Environment::default()).unwrap(),
            Value::Bool(true)
        );
        let reference = InstanceReference {
            root_instance_id: "root".to_string(),
            instance_id: "child".to_string(),
            machine_id: "worker".to_string(),
            machine_version: 1,
        };
        let environment = Environment {
            values: BTreeMap::from([
                (
                    "left".to_string(),
                    Value::InstanceReference(reference.clone()),
                ),
                ("right".to_string(), Value::InstanceReference(reference)),
            ]),
        };
        assert_eq!(
            evaluate("left == right", &environment).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            evaluate("left != null", &environment).unwrap(),
            Value::Bool(true)
        );
    }

    #[test]
    fn dynamic_composite_equality_is_recursive_and_numeric_type_sensitive() {
        let environment = TypeEnvironment::default();
        for (expression, expected) in [
            ("[1] == [1.0]", false),
            ("[1] != [1.0]", true),
            ("{'x': 1} == {'x': 1.0}", false),
            ("{'x': 1} != {'x': 1.0}", true),
            ("1 in [1.0]", false),
            ("[1, 2] == [2, 1]", false),
            ("{'x': 1, 'y': 2} == {'y': 2, 'x': 1}", true),
            ("[{'x': [1, 2.0]}] == [{'x': [1, 2.0]}]", true),
            ("[{'x': [1, 2]}] == [{'x': [1, 2.0]}]", false),
        ] {
            check(expression, "/guard", &environment, &CelType::Bool)
                .unwrap_or_else(|error| panic!("{expression}: {error:?}"));
            assert_eq!(
                evaluate_boolean(expression, &Environment::default()).unwrap(),
                expected,
                "{expression}"
            );
        }
        assert!(check("1 == 1.0", "/guard", &environment, &CelType::Bool).is_err());
    }
}
