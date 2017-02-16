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
    /// The certificate management attributes.
    /// </summary>
    public partial class CertificateAttributes : Attributes
    {
        /// <summary>
        /// Initializes a new instance of the CertificateAttributes class.
        /// </summary>
        public CertificateAttributes() { }

        /// <summary>
        /// Initializes a new instance of the CertificateAttributes class.
        /// </summary>
        /// <param name="enabled">Determines whether the object is
        /// enabled.</param>
        /// <param name="notBefore">Not before date in UTC.</param>
        /// <param name="expires">Expiry date in UTC.</param>
        /// <param name="created">Creation time in UTC.</param>
        /// <param name="updated">Last updated time in UTC.</param>
        public CertificateAttributes(bool? enabled = default(bool?), DateTime? notBefore = default(DateTime?), DateTime? expires = default(DateTime?), DateTime? created = default(DateTime?), DateTime? updated = default(DateTime?))
            : base(enabled, notBefore, expires, created, updated)
        {
        }

    }
}
