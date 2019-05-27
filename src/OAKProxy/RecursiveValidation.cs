// Forked from Public Domain code
// https://github.com/jwcarroll/recursive-validator/

using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace OAKProxy
{
    public class ValidateObjectAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (value != null)
            {
                var results = new List<ValidationResult>();
                var context = new ValidationContext(value, validationContext, validationContext.Items);

                Validator.TryValidateObject(value, context, results, true);

                if (results.Count != 0)
                {
                    var members = results.SelectMany(r => r.MemberNames.Select(n => $"{validationContext.MemberName}.{n}")).ToArray();
                    var errors = String.Join(',', results.Select(r => r.ErrorMessage));
                    return new CompositeValidationResult(errors, members, results);
                }
            }

            return ValidationResult.Success;
        }
    }

    public class ValidateCollectionAttribute : ValidationAttribute
    {
        public Type ValidationType { get; set; }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (value != null)
            {
                if (value is IEnumerable enumerable)
                {
                    var validators = GetValidators().ToList();
                    var index = 0;

                    var allResults = new List<ValidationResult>();
                    foreach (var val in enumerable)
                    {
                        var results = new List<ValidationResult>();
                        var context = new ValidationContext(val, validationContext, validationContext.Items);

                        if (ValidationType != null)
                        {
                            Validator.TryValidateValue(val, context, results, validators);
                        }
                        else
                        {
                            Validator.TryValidateObject(val, context, results, true);
                        }

                        foreach(var result in results)
                        {
                            var memberNames = result.MemberNames.Select(n => $"[{index}].{n}").ToArray();
                            allResults.Add(new ValidationResult(result.ErrorMessage, memberNames));
                        }

                        ++index;
                    }

                    if (allResults.Count != 0)
                    {
                        var members = allResults.SelectMany(r => r.MemberNames.Select(n => $"{validationContext.MemberName}{n}"));
                        var errors = String.Join(',', allResults.Select(r => r.ErrorMessage));
                        return new CompositeValidationResult(errors, members, allResults);
                    }
                }
                else
                {
                    var names = new String[] { validationContext.MemberName };
                    return new CompositeValidationResult("Value is not enumerable.", names, null);
                }
            }

            return ValidationResult.Success;
        }

        private IEnumerable<ValidationAttribute> GetValidators()
        {
            if (ValidationType == null) yield break;

            yield return (ValidationAttribute)Activator.CreateInstance(ValidationType);
        }
    }

    public class CompositeValidationResult : ValidationResult
    {
        public ICollection<ValidationResult> Results { get; }

        public CompositeValidationResult(string errorMessage, IEnumerable<string> memberNames, ICollection<ValidationResult> results) : 
            base(errorMessage, memberNames)
        {
            Results = results;
        }

        protected CompositeValidationResult(ValidationResult validationResult) : base(validationResult) { }
    }
}