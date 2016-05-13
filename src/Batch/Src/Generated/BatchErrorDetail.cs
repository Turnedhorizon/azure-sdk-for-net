//****************************************
// This file was autogenerated by a tool.
// Do not modify it.
//****************************************
namespace Microsoft.Azure.Batch
{
    using Models = Microsoft.Azure.Batch.Protocol.Models;
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// An item of additional information included in a <see cref="BatchError"/>.
    /// </summary>
    public partial class BatchErrorDetail : IPropertyMetadata
    {
        private readonly string key;
        private readonly string value;

        #region Constructors

        internal BatchErrorDetail(Models.BatchErrorDetail protocolObject)
        {
            this.key = protocolObject.Key;
            this.value = protocolObject.Value;
        }

        #endregion Constructors

        #region BatchErrorDetail

        /// <summary>
        /// Gets an identifier specifying the meaning of the <see cref="Value"/> property.
        /// </summary>
        public string Key
        {
            get { return this.key; }
        }

        /// <summary>
        /// Gets the additional information included with the <see cref="BatchError"/>.
        /// </summary>
        public string Value
        {
            get { return this.value; }
        }

        #endregion // BatchErrorDetail

        #region IPropertyMetadata

        bool IModifiable.HasBeenModified
        {
            //This class is compile time readonly so it cannot have been modified
            get { return false; }
        }

        bool IReadOnly.IsReadOnly
        {
            get { return true; }
            set
            {
                // This class is compile time readonly already
            }
        }

        #endregion // IPropertyMetadata

        #region Internal/private methods


        /// <summary>
        /// Converts a collection of protocol layer objects to object layer collection objects.
        /// </summary>
        internal static IList<BatchErrorDetail> ConvertFromProtocolCollection(IEnumerable<Models.BatchErrorDetail> protoCollection)
        {
            ConcurrentChangeTrackedModifiableList<BatchErrorDetail> converted = UtilitiesInternal.CollectionToThreadSafeCollectionIModifiable(
                items: protoCollection,
                objectCreationFunc: o => new BatchErrorDetail(o));

            return converted;
        }

        /// <summary>
        /// Converts a collection of protocol layer objects to object layer collection objects, in a frozen state.
        /// </summary>
        internal static IList<BatchErrorDetail> ConvertFromProtocolCollectionAndFreeze(IEnumerable<Models.BatchErrorDetail> protoCollection)
        {
            ConcurrentChangeTrackedModifiableList<BatchErrorDetail> converted = UtilitiesInternal.CollectionToThreadSafeCollectionIModifiable(
                items: protoCollection,
                objectCreationFunc: o => new BatchErrorDetail(o).Freeze());

            converted = UtilitiesInternal.CreateObjectWithNullCheck(converted, o => o.Freeze());

            return converted;
        }

        /// <summary>
        /// Converts a collection of protocol layer objects to object layer collection objects, with each object marked readonly
        /// and returned as a readonly collection.
        /// </summary>
        internal static IReadOnlyList<BatchErrorDetail> ConvertFromProtocolCollectionReadOnly(IEnumerable<Models.BatchErrorDetail> protoCollection)
        {
            IReadOnlyList<BatchErrorDetail> converted =
                UtilitiesInternal.CreateObjectWithNullCheck(
                    UtilitiesInternal.CollectionToNonThreadSafeCollection(
                        items: protoCollection,
                        objectCreationFunc: o => new BatchErrorDetail(o).Freeze()), o => o.AsReadOnly());

            return converted;
        }

        #endregion // Internal/private methods
    }
}