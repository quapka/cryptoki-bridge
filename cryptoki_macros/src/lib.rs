use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, spanned::Spanned, token::Pub, ItemFn};

extern crate proc_macro;

/// Generates multiple implementations for linux and windows, modifying the function abi and visibility
///
#[proc_macro_attribute]
pub fn cryptoki_function(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    let input = set_public_visibility(input);

    // TODO: update the wrapper and use stdcall (or alternative) for windows,
    // TODO: consider C-unwrap for linux
    let linux_input = add_extern_abi_modifier(input.clone(), "C");
    let windows_input = add_extern_abi_modifier(input, "C");

    let expanded = quote! {
        #[no_mangle]
        #[allow(non_snake_case)]
        #[cfg(target_os = "windows")]
        #windows_input

        #[no_mangle]
        #[allow(non_snake_case)]
        #[cfg(target_os = "linux")]
        #linux_input
    };

    expanded.into()
}

/// Adds `extern abi_type` to the function signature
fn add_extern_abi_modifier(mut input: ItemFn, abi_type: &str) -> ItemFn {
    let _ = input.sig.abi.insert(syn::Abi {
        extern_token: Default::default(),
        name: Some(syn::LitStr::new(abi_type, input.sig.abi.span())),
    });
    input
}

/// Sets the visibility of the function to public
fn set_public_visibility(mut input: ItemFn) -> ItemFn {
    input.vis = syn::Visibility::Public(Pub(input.vis.span()));
    input
}
