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
    using Microsoft.Azure.KeyVault.WebKey;

    /// <summary>
    /// A KeyBundle consisting of a WebKey plus its attributes.
    /// </summary>
    public partial class KeyBundle
    {
        /// <summary>
        /// Initializes a new instance of the KeyBundle class.
        /// </summary>
        public KeyBundle() { }

        /// <summary>
        /// Initializes a new instance of the KeyBundle class.
        /// </summary>
        /// <param name="key">The Json web key.</param>
        /// <param name="attributes">The key management attributes.</param>
        /// <param name="tags">Application specific metadata in the form of
        /// key-value pairs.</param>
        /// <param name="managed">True if the key's lifetime is managed by key
        /// vault. If this is a key backing a certificate, then managed will
        /// be true.</param>
        public KeyBundle(JsonWebKey key = default(JsonWebKey), KeyAttributes attributes = default(KeyAttributes), IDictionary<string, string> tags = default(IDictionary<string, string>), bool? managed = default(bool?))
        {
            Key = key;
            Attributes = attributes;
            Tags = tags;
            Managed = managed;
        }

        /// <summary>
        /// Gets or sets the Json web key.
        /// </summary>
        [JsonProperty(PropertyName = "key")]
        public JsonWebKey Key { get; set; }

        /// <summary>
        /// Gets or sets the key management attributes.
        /// </summary>
        [JsonProperty(PropertyName = "attributes")]
        public KeyAttributes Attributes { get; set; }

        /// <summary>
        /// Gets or sets application specific metadata in the form of
        /// key-value pairs.
        /// </summary>
        [JsonProperty(PropertyName = "tags")]
        public IDictionary<string, string> Tags { get; set; }

        /// <summary>
        /// Gets true if the key's lifetime is managed by key vault. If this
        /// is a key backing a certificate, then managed will be true.
        /// </summary>
        [JsonProperty(PropertyName = "managed")]
        public bool? Managed { get; private set; }

    }
}
