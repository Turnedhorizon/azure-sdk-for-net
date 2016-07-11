// Code generated by Microsoft (R) AutoRest Code Generator 0.17.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.KeyVault.Models
{
    using System;
    using System.Linq;
    using System.Collections.Generic;
    using Newtonsoft.Json;
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Microsoft.Rest.Azure;

    public partial class X509CertificateProperties
    {
        /// <summary>
        /// Initializes a new instance of the X509CertificateProperties class.
        /// </summary>
        public X509CertificateProperties() { }

        /// <summary>
        /// Initializes a new instance of the X509CertificateProperties class.
        /// </summary>
        /// <param name="subject">The subject name. Should be a valid X500 Distinguished Name.</param>
        /// <param name="ekus">The enhaunced key usage.</param>
        /// <param name="subjectAlternativeNames">The subject alternative names.</param>
        /// <param name="keyUsage">List of key usages.</param>
        /// <param name="validityInMonths">The subject alternate names.</param>
        public X509CertificateProperties(string subject = default(string), IList<string> ekus = default(IList<string>), SubjectAlternativeNames subjectAlternativeNames = default(SubjectAlternativeNames), IList<string> keyUsage = default(IList<string>), int? validityInMonths = default(int?))
        {
            Subject = subject;
            Ekus = ekus;
            SubjectAlternativeNames = subjectAlternativeNames;
            KeyUsage = keyUsage;
            ValidityInMonths = validityInMonths;
        }

        /// <summary>
        /// Gets or sets the subject name. Should be a valid X500
        /// Distinguished Name.
        /// </summary>
        [JsonProperty(PropertyName = "subject")]
        public string Subject { get; set; }

        /// <summary>
        /// Gets or sets the enhaunced key usage.
        /// </summary>
        [JsonProperty(PropertyName = "ekus")]
        public IList<string> Ekus { get; set; }

        /// <summary>
        /// Gets or sets the subject alternative names.
        /// </summary>
        [JsonProperty(PropertyName = "sans")]
        public SubjectAlternativeNames SubjectAlternativeNames { get; set; }

        /// <summary>
        /// Gets or sets list of key usages.
        /// </summary>
        [JsonProperty(PropertyName = "key_usage")]
        public IList<string> KeyUsage { get; set; }

        /// <summary>
        /// Gets or sets the subject alternate names.
        /// </summary>
        [JsonProperty(PropertyName = "validity_months")]
        public int? ValidityInMonths { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (this.ValidityInMonths < 0)
            {
                throw new ValidationException(ValidationRules.InclusiveMinimum, "ValidityInMonths", 0);
            }
        }
    }
}
