using Azure.AI.OpenAI;
using Azure.Identity;
using Microsoft.Extensions.AI;

namespace ContosoHR.Api.Chat;

/// <summary>
/// R5: no API keys anywhere. Authenticates to Azure OpenAI with
/// <see cref="DefaultAzureCredential"/> (Managed Identity in Azure, developer
/// credentials — az/Visual Studio/VS Code login — locally), never an
/// <c>ApiKeyCredential</c>. The resource's RBAC role assignment for whichever
/// identity this resolves to should be scoped to "Cognitive Services OpenAI User"
/// (least privilege for chat completions) — see README.md.
/// </summary>
public static class AzureOpenAIChatClientFactory
{
    public static IChatClient Create(string endpoint, string chatDeploymentName)
    {
        var azureClient = new AzureOpenAIClient(new Uri(endpoint), new DefaultAzureCredential());
        return azureClient.GetChatClient(chatDeploymentName).AsIChatClient();
    }
}
