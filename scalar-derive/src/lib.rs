use convert_case::Casing;
use darling::{util::Flag, FromDeriveInput, FromField, FromVariant};
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Ident};

#[derive(FromDeriveInput)]
#[darling(attributes(document), supports(struct_named))]
struct Document {
    identifier: Option<String>,
    title: Option<String>,
    singleton: Flag,
}

#[derive(FromDeriveInput)]
#[darling(supports(struct_newtype, struct_named))]
#[darling(attributes(field))]
struct ToEditorField {
    ident: syn::Ident,
    generics: syn::Generics,
    data: darling::ast::Data<(), FieldInfo>,
    editor_component: Option<String>,
}

#[derive(FromDeriveInput)]
#[darling(supports(enum_unit, enum_named))]
struct Enum {
    data: darling::ast::Data<EnumVariant, FieldInfo>,
}

#[derive(FromVariant)]
struct EnumVariant {
    ident: Ident,
    fields: darling::ast::Fields<FieldInfo>,
}

#[derive(FromField, Clone)]
#[darling(attributes(field))]
struct FieldInfo {
    ident: Option<syn::Ident>,
    ty: syn::Type,
    title: Option<String>,
    placeholder: Option<String>,
    editor_component: Option<String>,
    default: Option<syn::Lit>,
    label: Flag,
    sublabel: Flag,
}

#[derive(FromField, Clone)]
#[darling(attributes(validate))]
struct ValidateInfo {
    ident: Option<syn::Ident>,
    skip: Flag,
    with: Option<Ident>,
}

/// Sets up an enum for use in a Document. This macro does a couple of things:
/// 1. It derives serde's Serialize and Deserialize traits. Make sure you have serde installed!
/// 2. Sets up said serialization and deserialization to work the way the editor expects.
/// 3. Derives `ToEditorField` for the schema
#[proc_macro_attribute]
pub fn doc_enum(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input: proc_macro2::TokenStream = input.into();
    let output = quote! {
        #[derive(::serde::Serialize, ::serde::Deserialize, ::scalar_cms::Enum)]
        #[serde(tag = "type")]
        #input
    };
    output.into()
}

/// Derives `EditorField`.
///
/// # Panics
///
/// Panics if the input isn't a struct somehow.
#[proc_macro_derive(EditorField, attributes(field))]
pub fn struct_to_editor_field(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let struct_info = match ToEditorField::from_derive_input(&input) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(e.write_errors()),
    };

    let ident = struct_info.ident;
    let fields = struct_info
        .data
        .take_struct()
        .expect("a compiler error should've been returned, this has to be a struct");

    let component_key = if let Some(str) = struct_info.editor_component {
        quote! { Some(#str.into()) }
    } else {
        quote! { None }
    };

    match fields.style {
        darling::ast::Style::Tuple => {
            let field = fields
                .fields
                .first()
                .expect("there should always be at least one field");
            let field_ty = &field.ty;
            quote! {
                impl ::scalar_cms::editor_field::ToEditorField for #ident  {
                    fn to_editor_field(
                        default: Option<impl Into<#ident>>,
                        name: &'static str,
                        title: &'static str,
                        placeholder: Option<&'static str>,
                        validator: Option<&'static str>,
                        component_key: Option<&'static str>
                    ) -> ::scalar_cms::EditorField
                    where
                        Self: std::marker::Sized,
                    {
                        use ::scalar_cms::editor_field::ToEditorField;
                        <#field_ty>::to_editor_field(default.map(Into::into), name, title, placeholder, validator, component_key.or(#component_key))
                    }
                }

                impl From<#ident> for #field_ty {
                    fn from(val: #ident) -> Self {
                        val.0
                    }
                }
            }
            .into()
        }
        darling::ast::Style::Struct => {
            let fields = fields
                .iter()
                .map(|f| field_to_info_call(f.to_owned()))
                .collect::<Vec<_>>();

            let (impl_generics, ty_generics, where_clause) = struct_info.generics.split_for_impl();
            let ty = quote! { #ident #ty_generics };

            quote! {
                impl #impl_generics ::scalar_cms::editor_field::ToEditorField for #ty where #ty: ::serde::Serialize #where_clause {
                    fn to_editor_field(
                        default: Option<impl Into<#ty>>,
                        name: &'static str,
                        title: &'static str,
                        placeholder: Option<&'static str>,
                        validator: Option<&'static str>,
                        component_key: Option<&'static str>
                    ) -> ::scalar_cms::EditorField
                    where
                        Self: std::marker::Sized,
                    {
                        ::scalar_cms::EditorField {
                            name,
                            title,
                            placeholder,
                            required: true,
                            validator,
                            field_type: ::scalar_cms::EditorType::Struct {
                                default: default.map(Into::into).as_ref().map(::scalar_cms::serde_json::to_value).map(|v| v.expect("a struct that should serialize to json")),
                                component_key: component_key.map(Into::into).or(#component_key),
                                fields: vec![#(#fields),*]
                            }
                        }
                    }
                }
            }
            .into()
        }
        darling::ast::Style::Unit => unreachable!("it's impossible for this to be a unit struct"),
    }
}

#[proc_macro_derive(Enum)]
pub fn derive_enum(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let enum_info = match Enum::from_derive_input(&input) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(e.write_errors()),
    };
    let ident = input.ident;

    let variants: Vec<proc_macro2::TokenStream> = match enum_info.data {
        darling::ast::Data::Enum(variants) => variants
            .iter()
            .map(|v| {
                let ident = v.ident.to_string();
                let fields: Vec<proc_macro2::TokenStream> = v
                    .fields
                    .iter()
                    .map(|field| field_to_info_call(field.to_owned()))
                    .collect();

                let fields_tokens = if fields.is_empty() {
                    quote! { None }
                } else {
                    quote! { Some(vec![#(#fields),*]) }
                };

                quote! {
                    ::scalar_cms::editor_type::EnumVariant {
                        variant_name: #ident,
                        fields: #fields_tokens
                    }
                }
            })
            .collect(),
        darling::ast::Data::Struct(_) => unreachable!(),
    };

    let output = quote! {
        impl ::scalar_cms::editor_field::ToEditorField for #ident where Self: ::serde::Serialize {
            fn to_editor_field(default: Option<impl Into<Self>>, name: &'static str, title: &'static str, placeholder: Option<&'static str>, validator: Option<&'static str>, component_key: Option<&'static str>) -> ::scalar_cms::EditorField where Self: std::marker::Sized {
                ::scalar_cms::EditorField { name, title, placeholder, required: true, validator, field_type: ::scalar_cms::EditorType::Enum {
                    default: default.map(Into::into).map(::scalar_cms::serde_json::to_value).map(|v| v.expect("a struct that should serialize to json")),
                    component_key: component_key.map(Into::into),
                    variants: vec![#(#variants),*]
                } }
            }
        }
    };
    output.into()
}

/// Derives the document trait.
///
/// # Panics
///
/// Panics if the input is somehow a tuple struct that isn't caught.
#[proc_macro_derive(Document, attributes(document, field, validate))]
pub fn derive_document(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let document = match Document::from_derive_input(&input) {
        Ok(v) => v,
        Err(e) => {
            return TokenStream::from(e.write_errors());
        }
    };
    let struct_fields = match input.data {
        Data::Struct(st) => st.fields,
        _ => unreachable!(),
    };
    let ident = input.ident;

    let doc_identifier = document
        .identifier
        .unwrap_or_else(|| ident.to_string().to_case(convert_case::Case::Snake));

    let doc_title = document
        .title
        .unwrap_or_else(|| ident.to_string().to_case(convert_case::Case::Title));

    let singleton = document.singleton.is_present();

    let struct_field_infos = match struct_fields
        .iter()
        .map(FieldInfo::from_field)
        .collect::<Result<Vec<FieldInfo>, darling::Error>>()
    {
        Ok(f) => f,
        Err(e) => return TokenStream::from(e.write_errors()),
    };

    let document_label = match struct_field_infos
        .iter()
        .filter(|f| f.label.is_present())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => None,
        [one] => Some(cleanup_ident(
            one.ident
                .as_ref()
                .expect("this shouldn't be a tuple struct!!"),
        )),
        [head, tail @ ..] => {
            return tail
                .iter()
                .fold(
                    syn::Error::new(
                        head.label.span(),
                        "only one field can be defined as the label",
                    ),
                    |mut error, field| {
                        error.combine(syn::Error::new(
                            field.label.span(),
                            "only one field can be defined as the label",
                        ));
                        error
                    },
                )
                .into_compile_error()
                .into()
        }
    }
    .map_or(quote! { None }, |lit| quote! {Some(#lit)});

    let document_sub_label = match struct_field_infos
        .iter()
        .filter(|f| f.sublabel.is_present())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => None,
        [one] => Some(cleanup_ident(
            one.ident
                .as_ref()
                .expect("this shouldn't be a tuple struct!!"),
        )),
        [head, tail @ ..] => {
            return tail
                .iter()
                .fold(
                    syn::Error::new(
                        head.sublabel.span(),
                        "only one field can be defined as the sub label",
                    ),
                    |mut error, field| {
                        error.combine(syn::Error::new(
                            field.sublabel.span(),
                            "only one field can be defined as the sub label",
                        ));
                        error
                    },
                )
                .into_compile_error()
                .into()
        }
    }
    .map_or(quote! { None }, |lit| quote! {Some(#lit)});

    let struct_validators = match struct_fields
        .iter()
        .map(ValidateInfo::from_field)
        .collect::<Result<Vec<ValidateInfo>, darling::Error>>()
    {
        Ok(f) => f,
        Err(e) => return TokenStream::from(e.write_errors()),
    };

    let fields = struct_field_infos
        .iter()
        .map(|f| field_to_info_call(f.to_owned()))
        .collect::<Vec<_>>();

    let validators = struct_validators
        .iter()
        .filter(|&f| !f.skip.is_present())
        .map(|f| {
            let ident = f.ident.as_ref().expect("this shouldn't be a tuple struct!");
            let ident_str = ident.to_string();

            if let Some(fn_ident) = f.with.as_ref() {
                quote! {
                    (#ident_str.into(), #fn_ident(&self.#ident, ctx.for_field(#ident_str)).await)
                }
            } else {
                quote! {
                    (#ident_str.into(), ::scalar_cms::validations::Validate::validate(&self.#ident, ctx.for_field(#ident_str)).await)
                }
            }
        })
        .collect::<Vec<_>>();

    let validators_count = validators.len();

    let output = quote! {
        #[automatically_derived]
        impl Document for #ident {
            const IDENTIFIER: &'static str = #doc_identifier;
            const TITLE: &'static str = #doc_title;
            const LABEL: Option<&'static str> = #document_label;
            const SUB_LABEL: Option<&'static str> = #document_sub_label;
            const SINGLETON: bool = #singleton;

            fn fields() -> &'static [::scalar_cms::EditorField] {
                use ::scalar_cms::editor_field::ToEditorField;
                static FIELDS: ::std::sync::LazyLock<Box<[EditorField]>> =
                    ::std::sync::LazyLock::new(|| vec![
                        #(#fields),*
                    ].into_boxed_slice());

                &FIELDS
            }
        }

        #[automatically_derived]
        impl ::scalar_cms::validations::Validate for #ident {
            async fn validate<DB: ::scalar_cms::db::DatabaseConnection + ::scalar_cms::db::ContentActions<D> + Sync, D: ::scalar_cms::Document + Sync>(&self, ctx: ::scalar_cms::db::ValidationContext<'_, DB, D>) -> Result<(), ::scalar_cms::validations::ValidationError> {
                let results: [(::scalar_cms::validations::Field, Result<(), ::scalar_cms::validations::ValidationError>); #validators_count] = [#(#validators),*];

                let errors: Vec<::scalar_cms::validations::ErroredField> = results
                    .into_iter()
                    .filter_map(|(f, r)| r.err().map(|e| ::scalar_cms::validations::ErroredField { field: f, error: e}))
                    .collect();

                errors
                    .is_empty()
                    .then_some(())
                    .ok_or(::scalar_cms::validations::ValidationError::Composite(errors))
            }
        }
    };
    output.into()
}

fn field_to_info_call(field: FieldInfo) -> proc_macro2::TokenStream {
    let ty = field.ty;

    let ident = field
        .ident
        .map(|i| cleanup_ident(&i))
        .expect("this shouldn't be a tuple struct!!!!");
    let title = field
        .title
        .unwrap_or(ident.to_case(convert_case::Case::Title));
    let placeholder = if let Some(str) = field.placeholder {
        quote! { Some(#str) }
    } else {
        quote! { None }
    };
    let component_key = if let Some(str) = field.editor_component {
        quote! { Some(#str) }
    } else {
        quote! { None }
    };

    // let validator = match field.validate.is_present() {
    //     true => quote! { Some(stringify!(#ty)) },
    //     false => quote! { None },
    // };

    let default = match field.default {
        Some(lit) => quote! { Some(#lit) },
        None => {
            quote! { None::<#ty> }
        }
    };
    quote! {
        <#ty as ::scalar_cms::editor_field::ToEditorField>::to_editor_field(#default, #ident, #title, #placeholder, None, #component_key)
    }
}

/// cleans up idents which may start with r#, same as serde
fn cleanup_ident(ident: &Ident) -> String {
    ident.to_string().trim_start_matches("r#").to_string()
}
