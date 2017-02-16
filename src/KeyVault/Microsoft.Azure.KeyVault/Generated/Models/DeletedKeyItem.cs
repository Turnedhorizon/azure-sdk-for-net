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
    /// The deleted key item containing the deleted key metadata and
    /// information about deletion.
    /// </summary>
    public partial class DeletedKeyItem : KeyItem
    {
        /// <summary>
        /// Initializes a new instance of the DeletedKeyItem class.
        /// </summary>
        public DeletedKeyItem() { }

        /// <summary>
        /// Initializes a new instance of the DeletedKeyItem class.
        /// </summary>
        /// <param name="kid">Key identifier.</param>
        /// <param name="attributes">The key management attributes.</param>
        /// <param name="tags">Application specific metadata in the form of
        /// key-value pairs.</param>
        /// <param name="managed">True if the key's lifetime is managed by key
        /// vault. If this is a key backing a certificate, then managed will
        /// be true.</param>
        /// <param name="recoveryId">The url of the recovery object, used to
        /// identify and recover the deleted key.</param>
        /// <param name="scheduledPurgeDate">The time when the key is
        /// scheduled to be purged, in UTC</param>
        /// <param name="deletedDate">The time when the key was deleted, in
        /// UTC</param>
        public DeletedKeyItem(string kid = default(string), KeyAttributes attributes = default(KeyAttributes), IDictionary<string, string> tags = default(IDictionary<string, string>), bool? managed = default(bool?), string recoveryId = default(string), DateTime? scheduledPurgeDate = default(DateTime?), DateTime? deletedDate = default(DateTime?))
            : base(kid, attributes, tags, managed)
        {
            RecoveryId = recoveryId;
            ScheduledPurgeDate = scheduledPurgeDate;
            DeletedDate = deletedDate;
        }

        /// <summary>
        /// Gets or sets the url of the recovery object, used to identify and
        /// recover the deleted key.
        /// </summary>
        [JsonProperty(PropertyName = "recoveryId")]
        public string RecoveryId { get; set; }

        /// <summary>
        /// Gets the time when the key is scheduled to be purged, in UTC
        /// </summary>
        [JsonConverter(typeof(UnixTimeJsonConverter))]
        [JsonProperty(PropertyName = "scheduledPurgeDate")]
        public DateTime? ScheduledPurgeDate { get; private set; }

        /// <summary>
        /// Gets the time when the key was deleted, in UTC
        /// </summary>
        [JsonConverter(typeof(UnixTimeJsonConverter))]
        [JsonProperty(PropertyName = "deletedDate")]
        public DateTime? DeletedDate { get; private set; }

    }
}
