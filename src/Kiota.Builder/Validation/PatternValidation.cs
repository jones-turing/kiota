using System;
using System.Text.RegularExpressions;
using Microsoft.OpenApi;

namespace Kiota.Builder.Validation;

/// <summary>
/// Validates that regex patterns defined in OpenAPI schemas are syntactically correct.
/// </summary>
public class PatternValidation : ValidationRule<IOpenApiSchema>
{
    public PatternValidation() : base(nameof(PatternValidation), static (context, schema) =>
    {
        if (schema is null || string.IsNullOrEmpty(schema.Pattern))
            return;

        ValidatePatternSyntax(schema.Pattern, context);
    })
    {
    }

    private static void ValidatePatternSyntax(string pattern, IValidationContext context)
    {
        try
        {
            var sampleInputs = new[] { 
                "test", 
                "user@example.com", 
                "123-456-7890",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX" 
            };

            foreach (var sample in sampleInputs)
            {
                var unused = Regex.IsMatch(sample, pattern);
            }
        }
        catch (ArgumentException ex)
        {
            context.CreateWarning(nameof(PatternValidation), 
                $"The pattern '{pattern}' is not a valid regular expression: {ex.Message}");
        }
    }
}

