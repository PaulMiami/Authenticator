﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace PaulMiami.AspNetCore.Authentication.Authenticator {
    using System;
    using System.Reflection;
    
    
    /// <summary>
    ///    A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    public class Resources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        internal Resources() {
        }
        
        /// <summary>
        ///    Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("PaulMiami.AspNetCore.Authentication.Authenticator.Resources", typeof(Resources).GetTypeInfo().Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///    Overrides the current thread's CurrentUICulture property for all
        ///    resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///    Looks up a localized string similar to The number of digits must be between 6 and 8..
        /// </summary>
        public static string Exception_InvalidNumberOfDigits {
            get {
                return ResourceManager.GetString("Exception_InvalidNumberOfDigits", resourceCulture);
            }
        }
        
        /// <summary>
        ///    Looks up a localized string similar to The period must be at least 30 seconds..
        /// </summary>
        public static string Exception_InvalidPeriodInSeconds {
            get {
                return ResourceManager.GetString("Exception_InvalidPeriodInSeconds", resourceCulture);
            }
        }
        
        /// <summary>
        ///    Looks up a localized string similar to The &apos;{0}&apos; option must be provided..
        /// </summary>
        public static string Exception_OptionMustBeProvided {
            get {
                return ResourceManager.GetString("Exception_OptionMustBeProvided", resourceCulture);
            }
        }
    }
}
