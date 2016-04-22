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

    public partial class Attributes
    {
        /// <summary>
        /// Initializes a new instance of the Attributes class.
        /// </summary>
        public Attributes() { }

        /// <summary>
        /// Initializes a new instance of the Attributes class.
        /// </summary>
        public Attributes(bool? enabled = default(bool?), long? notBefore = default(long?), long? expires = default(long?), long? created = default(long?), long? updated = default(long?))
        {
            Enabled = enabled;
            NotBefore = notBefore;
            Expires = expires;
            Created = created;
            Updated = updated;
        }

        /// <summary>
        /// Determines whether the key is enabled
        /// </summary>
        [JsonProperty(PropertyName = "enabled")]
        public bool? Enabled { get; set; }

        /// <summary>
        /// Not before date in UTC
        /// </summary>
        [JsonProperty(PropertyName = "nbf")]
        public long? NotBefore { get; set; }

        /// <summary>
        /// Expiry date in UTC
        /// </summary>
        [JsonProperty(PropertyName = "exp")]
        public long? Expires { get; set; }

        /// <summary>
        /// Creation time in UTC
        /// </summary>
        [JsonProperty(PropertyName = "created")]
        public long? Created { get; private set; }

        /// <summary>
        /// Last updated time in UTC
        /// </summary>
        [JsonProperty(PropertyName = "updated")]
        public long? Updated { get; private set; }

    }
}
