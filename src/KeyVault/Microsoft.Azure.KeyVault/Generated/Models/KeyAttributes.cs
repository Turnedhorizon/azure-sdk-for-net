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

    public partial class KeyAttributes : Attributes
    {
        /// <summary>
        /// Initializes a new instance of the KeyAttributes class.
        /// </summary>
        public KeyAttributes() { }

        /// <summary>
        /// Initializes a new instance of the KeyAttributes class.
        /// </summary>
        /// <param name="enabled">Determines whether the object is enabled</param>
        /// <param name="notBefore">Not before date in UTC</param>
        /// <param name="expires">Expiry date in UTC</param>
        /// <param name="created">Creation time in UTC</param>
        /// <param name="updated">Last updated time in UTC</param>
        public KeyAttributes(bool? enabled = default(bool?), DateTime? notBefore = default(DateTime?), DateTime? expires = default(DateTime?), DateTime? created = default(DateTime?), DateTime? updated = default(DateTime?))
            : base(enabled, notBefore, expires, created, updated)
        {
        }

    }
}
