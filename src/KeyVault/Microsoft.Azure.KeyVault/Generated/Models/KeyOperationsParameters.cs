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
    /// The key operations parameters.
    /// </summary>
    public partial class KeyOperationsParameters
    {
        /// <summary>
        /// Initializes a new instance of the KeyOperationsParameters class.
        /// </summary>
        public KeyOperationsParameters() { }

        /// <summary>
        /// Initializes a new instance of the KeyOperationsParameters class.
        /// </summary>
        /// <param name="algorithm">algorithm identifier. Possible values
        /// include: 'RSA-OAEP', 'RSA1_5'</param>
        public KeyOperationsParameters(string algorithm, byte[] value)
        {
            Algorithm = algorithm;
            Value = value;
        }

        /// <summary>
        /// Gets or sets algorithm identifier. Possible values include:
        /// 'RSA-OAEP', 'RSA1_5'
        /// </summary>
        [JsonProperty(PropertyName = "alg")]
        public string Algorithm { get; set; }

        /// <summary>
        /// </summary>
        [JsonConverter(typeof(Base64UrlJsonConverter))]
        [JsonProperty(PropertyName = "value")]
        public byte[] Value { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (Algorithm == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "Algorithm");
            }
            if (Value == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "Value");
            }
            if (this.Algorithm != null)
            {
                if (this.Algorithm.Length < 1)
                {
                    throw new ValidationException(ValidationRules.MinLength, "Algorithm", 1);
                }
            }
        }
    }
}
