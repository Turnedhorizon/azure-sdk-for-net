// Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
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

    public partial class SecretUpdateParameters
    {
        /// <summary>
        /// Initializes a new instance of the SecretUpdateParameters class.
        /// </summary>
        public SecretUpdateParameters() { }

        /// <summary>
        /// Initializes a new instance of the SecretUpdateParameters class.
        /// </summary>
        public SecretUpdateParameters(SecretAttributes attributes = default(SecretAttributes), string contentType = default(string), IDictionary<string, string> tags = default(IDictionary<string, string>))
        {
            Attributes = attributes;
            ContentType = contentType;
            Tags = tags;
        }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "attributes")]
        public SecretAttributes Attributes { get; set; }

        /// <summary>
        /// Type of the secret value such as a password
        /// </summary>
        [JsonProperty(PropertyName = "contentType")]
        public string ContentType { get; set; }

        /// <summary>
        /// Application-specific metadata in the form of key-value pairs
        /// </summary>
        [JsonProperty(PropertyName = "tags")]
        public IDictionary<string, string> Tags { get; set; }

    }
}
