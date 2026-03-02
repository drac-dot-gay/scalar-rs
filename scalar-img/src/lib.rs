use scalar_cms::{
    db::{ContentActions, ValidationContext},
    editor_field::ToEditorField,
    validations::{ErroredField, Validate, ValidationError},
    DatabaseConnection, Document, EditorField,
};
use serde::{Deserialize, Serialize};

use url::Url;

#[cfg(feature = "s3")]
pub mod bucket;
#[cfg(feature = "s3")]
pub use bucket::*;

/// Indicates no data (similar to the unit type ())
/// This exists for the sole purpose of thwarting databases that trim
/// null field types.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Null([(); 0]);

impl ToEditorField for Null {
    fn to_editor_field(
        _default: Option<impl Into<Self>>,
        name: &'static str,
        title: &'static str,
        placeholder: Option<&'static str>,
        validator: Option<&'static str>,
        component_key: Option<&'static str>,
    ) -> EditorField
    where
        Self: std::marker::Sized,
    {
        EditorField {
            name,
            title,
            placeholder,
            required: true,
            validator,
            field_type: scalar_cms::EditorType::Null {
                component_key: component_key.map(Into::into),
            },
        }
    }
}

#[derive(EditorField, Serialize, Deserialize)]
#[field(editor_component = "image")]
#[derive(Debug)]
pub struct ImageData<D: ToEditorField> {
    pub url: Url,
    pub additional_data: D,
}

pub type Image = ImageData<Null>;

impl<D: ToEditorField + Validate + Sync> Validate for ImageData<D> {
    async fn validate<DB: DatabaseConnection + ContentActions<DD> + Sync, DD: Document + Sync>(
        &self,
        ctx: ValidationContext<'_, DB, DD>,
    ) -> Result<(), scalar_cms::validations::ValidationError> {
        self.additional_data.validate(ctx).await
    }
}

#[derive(EditorField, Debug, Serialize, Deserialize)]
#[field(editor_component = "cropped-image")]
/// A cropped image with additional data.
/// The VALIDATE flag is a workaround for implementing traits in rust.
pub struct CroppedImageData<D: ToEditorField, const VALIDATE: bool = true> {
    pub url: Url,
    pub gravity_x: f32,
    pub gravity_y: f32,
    pub additional_data: D,
}

pub type CroppedImage = CroppedImageData<Null, false>;

impl<const VALIDATE: bool, D: ToEditorField> CroppedImageData<D, VALIDATE> {
    #[inline]
    fn validate_inner(
        &self,
        additional_result: Result<(), ValidationError>,
    ) -> Result<(), ValidationError> {
        let results = [
            (0.0..=1.0).contains(&self.gravity_x).then_some(()).ok_or((
                "gravity_x",
                ValidationError::Single("gravity_x must be between 0 and 1".into()),
            )),
            (0.0..=1.0).contains(&self.gravity_y).then_some(()).ok_or((
                "gravity_y",
                ValidationError::Single("gravity_y must be between 0 and 1".into()),
            )),
            additional_result.map_err(|e| ("additional_data", e)),
        ];
        // if all errors are ok, don't bother even allocating a vec
        if results.iter().all(Result::is_ok) {
            Ok(())
        } else {
            Err(ValidationError::Composite(
                results
                    .into_iter()
                    .filter_map(|r| {
                        r.err().map(|(field, error)| ErroredField {
                            field: field.into(),
                            error,
                        })
                    })
                    .collect(),
            ))
        }
    }
}

impl<D: ToEditorField + Validate + Sync> Validate for CroppedImageData<D, true> {
    async fn validate<DB: DatabaseConnection + ContentActions<DD> + Sync, DD: Document + Sync>(
        &self,
        ctx: ValidationContext<'_, DB, DD>,
    ) -> Result<(), scalar_cms::validations::ValidationError> {
        self.validate_inner(self.additional_data.validate(ctx).await)
    }
}

impl<D: ToEditorField + Send + Sync> Validate for CroppedImageData<D, false> {
    async fn validate<DB: DatabaseConnection, DD: Document>(
        &self,
        _ctx: ValidationContext<'_, DB, DD>,
    ) -> Result<(), scalar_cms::validations::ValidationError> {
        self.validate_inner(Ok(()))
    }
}

#[derive(EditorField, Debug, Serialize, Deserialize)]
#[field(editor_component = "file")]
pub struct FileData<D: ToEditorField> {
    pub url: Url,
    pub additional_data: D,
}

pub type File = FileData<Null>;

impl<D: ToEditorField + Validate + Send + Sync> Validate for FileData<D> {
    async fn validate<
        DB: DatabaseConnection + ContentActions<DD> + Sync,
        DD: Document + Send + Sync,
    >(
        &self,
        ctx: ValidationContext<'_, DB, DD>,
    ) -> Result<(), scalar_cms::validations::ValidationError> {
        self.additional_data.validate(ctx).await
    }
}
