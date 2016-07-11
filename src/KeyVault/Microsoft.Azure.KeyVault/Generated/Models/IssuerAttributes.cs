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

    public partial class IssuerAttributes
    {
        /// <summary>
        /// Initializes a new instance of the IssuerAttributes class.
        /// </summary>
        public IssuerAttributes() { }

        /// <summary>
        /// Initializes a new instance of the IssuerAttributes class.
        /// </summary>
        /// <param name="enabled">Determines whether the issuer is enabled</param>
        /// <param name="created">Creation time in UTC</param>
        /// <param name="updated">Last updated time in UTC</param>
        public IssuerAttributes(bool? enabled = default(bool?), DateTime? created = default(DateTime?), DateTime? updated = default(DateTime?))
        {
            Enabled = enabled;
            Created = created;
            Updated = updated;
        }

        /// <summary>
        /// Gets or sets determines whether the issuer is enabled
        /// </summary>
        [JsonProperty(PropertyName = "enabled")]
        public bool? Enabled { get; set; }

        /// <summary>
        /// Gets creation time in UTC
        /// </summary>
        [JsonConverter(typeof(UnixTimeJsonConverter))]
        [JsonProperty(PropertyName = "created")]
        public DateTime? Created { get; private set; }

        /// <summary>
        /// Gets last updated time in UTC
        /// </summary>
        [JsonConverter(typeof(UnixTimeJsonConverter))]
        [JsonProperty(PropertyName = "updated")]
        public DateTime? Updated { get; private set; }

    }
}
