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
    /// The <see cref="CloudJobSchedule.JobSpecification"/> of a <see cref="CloudJobSchedule"/>.
    /// </summary>
    public partial class JobSpecification : ITransportObjectProvider<Models.JobSpecification>, IPropertyMetadata
    {
        private class PropertyContainer : PropertyCollection
        {
            public readonly PropertyAccessor<IList<EnvironmentSetting>> CommonEnvironmentSettingsProperty;
            public readonly PropertyAccessor<JobConstraints> ConstraintsProperty;
            public readonly PropertyAccessor<string> DisplayNameProperty;
            public readonly PropertyAccessor<JobManagerTask> JobManagerTaskProperty;
            public readonly PropertyAccessor<JobPreparationTask> JobPreparationTaskProperty;
            public readonly PropertyAccessor<JobReleaseTask> JobReleaseTaskProperty;
            public readonly PropertyAccessor<IList<MetadataItem>> MetadataProperty;
            public readonly PropertyAccessor<PoolInformation> PoolInformationProperty;
            public readonly PropertyAccessor<int?> PriorityProperty;
            public readonly PropertyAccessor<bool?> UsesTaskDependenciesProperty;

            public PropertyContainer() : base(BindingState.Unbound)
            {
                this.CommonEnvironmentSettingsProperty = this.CreatePropertyAccessor<IList<EnvironmentSetting>>("CommonEnvironmentSettings", BindingAccess.Read | BindingAccess.Write);
                this.ConstraintsProperty = this.CreatePropertyAccessor<JobConstraints>("Constraints", BindingAccess.Read | BindingAccess.Write);
                this.DisplayNameProperty = this.CreatePropertyAccessor<string>("DisplayName", BindingAccess.Read | BindingAccess.Write);
                this.JobManagerTaskProperty = this.CreatePropertyAccessor<JobManagerTask>("JobManagerTask", BindingAccess.Read | BindingAccess.Write);
                this.JobPreparationTaskProperty = this.CreatePropertyAccessor<JobPreparationTask>("JobPreparationTask", BindingAccess.Read | BindingAccess.Write);
                this.JobReleaseTaskProperty = this.CreatePropertyAccessor<JobReleaseTask>("JobReleaseTask", BindingAccess.Read | BindingAccess.Write);
                this.MetadataProperty = this.CreatePropertyAccessor<IList<MetadataItem>>("Metadata", BindingAccess.Read | BindingAccess.Write);
                this.PoolInformationProperty = this.CreatePropertyAccessor<PoolInformation>("PoolInformation", BindingAccess.Read | BindingAccess.Write);
                this.PriorityProperty = this.CreatePropertyAccessor<int?>("Priority", BindingAccess.Read | BindingAccess.Write);
                this.UsesTaskDependenciesProperty = this.CreatePropertyAccessor<bool?>("UsesTaskDependencies", BindingAccess.Read | BindingAccess.Write);
            }

            public PropertyContainer(Models.JobSpecification protocolObject) : base(BindingState.Bound)
            {
                this.CommonEnvironmentSettingsProperty = this.CreatePropertyAccessor(
                    EnvironmentSetting.ConvertFromProtocolCollection(protocolObject.CommonEnvironmentSettings),
                    "CommonEnvironmentSettings",
                    BindingAccess.Read | BindingAccess.Write);
                this.ConstraintsProperty = this.CreatePropertyAccessor(
                    UtilitiesInternal.CreateObjectWithNullCheck(protocolObject.Constraints, o => new JobConstraints(o)),
                    "Constraints",
                    BindingAccess.Read | BindingAccess.Write);
                this.DisplayNameProperty = this.CreatePropertyAccessor(
                    protocolObject.DisplayName,
                    "DisplayName",
                    BindingAccess.Read | BindingAccess.Write);
                this.JobManagerTaskProperty = this.CreatePropertyAccessor(
                    UtilitiesInternal.CreateObjectWithNullCheck(protocolObject.JobManagerTask, o => new JobManagerTask(o)),
                    "JobManagerTask",
                    BindingAccess.Read | BindingAccess.Write);
                this.JobPreparationTaskProperty = this.CreatePropertyAccessor(
                    UtilitiesInternal.CreateObjectWithNullCheck(protocolObject.JobPreparationTask, o => new JobPreparationTask(o)),
                    "JobPreparationTask",
                    BindingAccess.Read | BindingAccess.Write);
                this.JobReleaseTaskProperty = this.CreatePropertyAccessor(
                    UtilitiesInternal.CreateObjectWithNullCheck(protocolObject.JobReleaseTask, o => new JobReleaseTask(o)),
                    "JobReleaseTask",
                    BindingAccess.Read | BindingAccess.Write);
                this.MetadataProperty = this.CreatePropertyAccessor(
                    MetadataItem.ConvertFromProtocolCollection(protocolObject.Metadata),
                    "Metadata",
                    BindingAccess.Read | BindingAccess.Write);
                this.PoolInformationProperty = this.CreatePropertyAccessor(
                    UtilitiesInternal.CreateObjectWithNullCheck(protocolObject.PoolInfo, o => new PoolInformation(o)),
                    "PoolInformation",
                    BindingAccess.Read | BindingAccess.Write);
                this.PriorityProperty = this.CreatePropertyAccessor(
                    protocolObject.Priority,
                    "Priority",
                    BindingAccess.Read | BindingAccess.Write);
                this.UsesTaskDependenciesProperty = this.CreatePropertyAccessor(
                    protocolObject.UsesTaskDependencies,
                    "UsesTaskDependencies",
                    BindingAccess.Read | BindingAccess.Write);
            }
        }

        private readonly PropertyContainer propertyContainer;

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="JobSpecification"/> class.
        /// </summary>
        public JobSpecification()
        {
            this.propertyContainer = new PropertyContainer();
        }

        internal JobSpecification(Models.JobSpecification protocolObject)
        {
            this.propertyContainer = new PropertyContainer(protocolObject);
        }

        #endregion Constructors

        #region JobSpecification

        /// <summary>
        /// Gets or sets a list of common environment variable settings.
        /// </summary>
        /// <remarks>
        /// These environment variables are set for all tasks in jobs created under this <see cref="CloudJobSchedule"/> (including 
        /// the Job Manager, Job Preparation and Job Release tasks).
        /// </remarks>
        public IList<EnvironmentSetting> CommonEnvironmentSettings
        {
            get { return this.propertyContainer.CommonEnvironmentSettingsProperty.Value; }
            set
            {
                this.propertyContainer.CommonEnvironmentSettingsProperty.Value = ConcurrentChangeTrackedModifiableList<EnvironmentSetting>.TransformEnumerableToConcurrentModifiableList(value);
            }
        }

        /// <summary>
        /// Gets or sets the execution constraints for jobs created via this <see cref="JobSpecification"/>.
        /// </summary>
        public JobConstraints Constraints
        {
            get { return this.propertyContainer.ConstraintsProperty.Value; }
            set { this.propertyContainer.ConstraintsProperty.Value = value; }
        }

        /// <summary>
        /// Gets or sets a display name for all jobs created via this <see cref="JobSpecification"/>.
        /// </summary>
        public string DisplayName
        {
            get { return this.propertyContainer.DisplayNameProperty.Value; }
            set { this.propertyContainer.DisplayNameProperty.Value = value; }
        }

        /// <summary>
        /// Gets or sets details of a Job Manager task to be launched when a job is created via this <see cref="JobSpecification"/>.
        /// </summary>
        public JobManagerTask JobManagerTask
        {
            get { return this.propertyContainer.JobManagerTaskProperty.Value; }
            set { this.propertyContainer.JobManagerTaskProperty.Value = value; }
        }

        /// <summary>
        /// Gets or sets the Job Preparation task for jobs created via this <see cref="JobSpecification"/>.
        /// </summary>
        /// <remarks>
        /// The Batch service will run the Job Preparation task on a compute node before starting any tasks of that job on 
        /// that compute node.
        /// </remarks>
        public JobPreparationTask JobPreparationTask
        {
            get { return this.propertyContainer.JobPreparationTaskProperty.Value; }
            set { this.propertyContainer.JobPreparationTaskProperty.Value = value; }
        }

        /// <summary>
        /// Gets or sets the Job Release task for jobs created via this <see cref="JobSpecification"/>. 
        /// </summary>
        /// <remarks>
        /// The Batch service runs the Job Release task when the job ends, on each compute node where any task of the job 
        /// has run.
        /// </remarks>
        public JobReleaseTask JobReleaseTask
        {
            get { return this.propertyContainer.JobReleaseTaskProperty.Value; }
            set { this.propertyContainer.JobReleaseTaskProperty.Value = value; }
        }

        /// <summary>
        /// Gets or sets a list of name-value pairs associated with jobs created via this <see cref="JobSpecification"/> 
        /// as metadata.
        /// </summary>
        public IList<MetadataItem> Metadata
        {
            get { return this.propertyContainer.MetadataProperty.Value; }
            set
            {
                this.propertyContainer.MetadataProperty.Value = ConcurrentChangeTrackedModifiableList<MetadataItem>.TransformEnumerableToConcurrentModifiableList(value);
            }
        }

        /// <summary>
        /// Gets or sets the pool on which the Batch service runs the tasks of jobs created via this <see cref="JobSpecification"/>.
        /// </summary>
        public PoolInformation PoolInformation
        {
            get { return this.propertyContainer.PoolInformationProperty.Value; }
            set { this.propertyContainer.PoolInformationProperty.Value = value; }
        }

        /// <summary>
        /// Gets or sets the priority of jobs created via this <see cref="JobSpecification"/>.
        /// </summary>
        /// <remarks>
        ///  Priority values can range from -1000 to 1000, with -1000 being the lowest priority and 1000 being the highest 
        /// priority.
        /// </remarks>
        public int? Priority
        {
            get { return this.propertyContainer.PriorityProperty.Value; }
            set { this.propertyContainer.PriorityProperty.Value = value; }
        }

        /// <summary>
        /// Gets or sets whether tasks in jobs created under this <see cref="CloudJobSchedule"/> can define dependencies 
        /// on each other.
        /// </summary>
        /// <remarks>
        /// The default value is false.
        /// </remarks>
        public bool? UsesTaskDependencies
        {
            get { return this.propertyContainer.UsesTaskDependenciesProperty.Value; }
            set { this.propertyContainer.UsesTaskDependenciesProperty.Value = value; }
        }

        #endregion // JobSpecification

        #region IPropertyMetadata

        bool IModifiable.HasBeenModified
        {
            get { return this.propertyContainer.HasBeenModified; }
        }

        bool IReadOnly.IsReadOnly
        {
            get { return this.propertyContainer.IsReadOnly; }
            set { this.propertyContainer.IsReadOnly = value; }
        }

        #endregion //IPropertyMetadata

        #region Internal/private methods
        /// <summary>
        /// Return a protocol object of the requested type.
        /// </summary>
        /// <returns>The protocol object of the requested type.</returns>
        Models.JobSpecification ITransportObjectProvider<Models.JobSpecification>.GetTransportObject()
        {
            Models.JobSpecification result = new Models.JobSpecification()
            {
                CommonEnvironmentSettings = UtilitiesInternal.ConvertToProtocolCollection(this.CommonEnvironmentSettings),
                Constraints = UtilitiesInternal.CreateObjectWithNullCheck(this.Constraints, (o) => o.GetTransportObject()),
                DisplayName = this.DisplayName,
                JobManagerTask = UtilitiesInternal.CreateObjectWithNullCheck(this.JobManagerTask, (o) => o.GetTransportObject()),
                JobPreparationTask = UtilitiesInternal.CreateObjectWithNullCheck(this.JobPreparationTask, (o) => o.GetTransportObject()),
                JobReleaseTask = UtilitiesInternal.CreateObjectWithNullCheck(this.JobReleaseTask, (o) => o.GetTransportObject()),
                Metadata = UtilitiesInternal.ConvertToProtocolCollection(this.Metadata),
                PoolInfo = UtilitiesInternal.CreateObjectWithNullCheck(this.PoolInformation, (o) => o.GetTransportObject()),
                Priority = this.Priority,
                UsesTaskDependencies = this.UsesTaskDependencies,
            };

            return result;
        }


        #endregion // Internal/private methods
    }
}