namespace ContosoHR.Data;

/// <summary>
/// A chunk of HR policy content plus its ACL metadata. <see cref="AllowedRoles"/> is
/// the source of truth for who may see this document — it is meaningless unless the
/// retrieval layer actually applies it (see docs/threat-model.md#T05).
/// </summary>
public sealed record PolicyDocument(
    string Id,
    string FileName,
    string Content,
    DocumentClassification Classification,
    IReadOnlyList<EmployeeRole> AllowedRoles);
