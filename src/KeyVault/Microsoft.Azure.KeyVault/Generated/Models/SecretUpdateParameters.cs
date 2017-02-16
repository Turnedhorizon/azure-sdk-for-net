// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
// 
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

    /// <summary>
    /// The secret update parameters.
    /// </summary>
    public partial class SecretUpdateParameters
    {
        /// <summary>
        /// Initializes a new instance of the SecretUpdateParameters class.
        /// </summary>
        public SecretUpdateParameters() { }

        /// <summary>
        /// Initializes a new instance of the SecretUpdateParameters class.
        /// </summary>
        /// <param name="contentType">Type of the secret value such as a
        /// password.</param>
        /// <param name="secretAttributes">The secret management
        /// attributes.</param>
        /// <param name="tags">Application specific metadata in the form of
        /// key-value pairs.</param>
        public SecretUpdateParameters(string contentType = default(string), SecretAttributes secretAttributes = default(SecretAttributes), IDictionary<string, string> tags = default(IDictionary<string, string>))
        {
            ContentType = contentType;
            SecretAttributes = secretAttributes;
            Tags = tags;
        }

        /// <summary>
        /// Gets or sets type of the secret value such as a password.
        /// </summary>
        [JsonProperty(PropertyName = "contentType")]
        public string ContentType { get; set; }

        /// <summary>
        /// Gets or sets the secret management attributes.
        /// </summary>
        [JsonProperty(PropertyName = "attributes")]
        public SecretAttributes SecretAttributes { get; set; }

        /// <summary>
        /// Gets or sets application specific metadata in the form of
        /// key-value pairs.
        /// </summary>
        [JsonProperty(PropertyName = "tags")]
        public IDictionary<string, string> Tags { get; set; }

    }
}
