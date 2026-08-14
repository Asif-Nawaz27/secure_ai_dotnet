namespace ContosoHR.Data;

/// <summary>
/// Classification tag on a policy document. Enforcement of this tag is the
/// responsibility of the retrieval layer (see docs/threat-model.md#T05) — the tag
/// alone does nothing.
/// </summary>
public enum DocumentClassification
{
    Public,
    Restricted
}
