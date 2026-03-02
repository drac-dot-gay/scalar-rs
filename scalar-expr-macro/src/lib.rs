use proc_macro::TokenStream;
use unsynn::{
    AndAnd, DelimitedVec, Either, Equal, Ident, LeftAssocExpr, Literal, NotEqual, OrOr, Parse,
    ToTokenIter, TrailingDelimiter::Forbidden, quote, unsynn,
};
use unsynn::{Colon, Cons, Dollar, LiteralString, ToTokens};

unsynn! {
    keyword Field = "field";
    keyword Current = "current";
    struct ComparisonOp(Either<Equal, NotEqual>);
    type ComparisonExpr = DelimitedVec<Either<Cons<Dollar, Current>, Cons<Field, Colon, LiteralString>, Literal, Ident>, ComparisonOp, Forbidden, 2, 2>;

    struct CompositeOp(Either<AndAnd, OrOr>);
    type CompositeExpr = LeftAssocExpr<ComparisonExpr, CompositeOp>;

    type Expr = CompositeExpr;
}

#[proc_macro]
pub fn expression(token_stream: TokenStream) -> TokenStream {
    let expr = Expr::parse(&mut unsynn::TokenStream::from(token_stream).to_token_iter())
        .unwrap()
        .0;

    expr.iter().rfold(unsynn::TokenStream::new(), |temp, component| {
        let ts = component_to_token_stream(&component.value);
        if let Some(delimiter) = &component.delimiter {
            let operator = match delimiter.0 {
                Either::First(_) => quote! {And},
                Either::Second(_) => quote! {Or},
                _ => unreachable!(),
            };
            // if there's a delimiter here, temp already has the right hand side, easy!
            quote! {::scalar_expr::Expression::#operator {lhs: Box::new(#ts), rhs: Box::new(#temp)}}
        } else {
            ts
        }
    }).into()
}

fn component_to_token_stream(component: &ComparisonExpr) -> unsynn::TokenStream {
    let operator = match component[0]
        .delimiter
        .as_ref()
        .expect("expected an operator")
        .0
    {
        Either::First(_) => quote! {Equals},
        Either::Second(_) => quote! {NotEquals},
        _ => unreachable!(),
    };
    let lhs = match &component[0].value {
        Either::First(_) => quote! {::scalar_expr::Value::CurrentField},
        Either::Second(Cons { third, .. }) => {
            quote! {::scalar_expr::Value::Ident(#third)}
        }
        Either::Third(val) => {
            quote! {::scalar_expr::Value::Value(::scalar_expr::to_value(#val).unwrap())}
        }
        Either::Fourth(val) => {
            quote! {::scalar_expr::Value::Value(::scalar_expr::to_value(#val).unwrap())}
        }
    };
    let rhs = match &component[1].value {
        Either::First(_) => quote! {::scalar_expr::Value::CurrentField},
        Either::Second(Cons { third, .. }) => {
            quote! {::scalar_expr::Value::Ident(#third)}
        }
        Either::Third(val) => {
            quote! {::scalar_expr::Value::Value(::scalar_expr::to_value(#val).unwrap())}
        }
        Either::Fourth(val) => {
            quote! {::scalar_expr::Value::Value(::scalar_expr::to_value(#val).unwrap())}
        }
    };
    quote! {::scalar_expr::Expression::#operator {lhs: #lhs, rhs: #rhs}}
}
