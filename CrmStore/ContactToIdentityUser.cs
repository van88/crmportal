using System;

namespace CrmStore
{
    public static class ContactToIdentityUser
    {
        public static TUser ToIdentityUser<TUser>(this Contact contact) where TUser : IdentityUser<string>, new()
        {
            if (contact == null) return null;
            return new TUser()
            {
                Id                = contact.Id.ToString(),
                Email             = contact.EMailAddress1,
                PhoneNumber       = contact.MobilePhone,
                UserName          = contact.ddd_username,
                EmailConfirmed    = contact.ddd_emailconfirmed ?? false,
                PasswordHash      = contact.ddd_passwordhash,
                AccessFailedCount = contact.ddd_accessfailedcount ?? 0,
                LockoutEnabled    = contact.ddd_lockoutenabled ?? false,
                LockoutEndDateUtc = contact.ddd_lockoutenddate,
                TwoFactorEnabled  = contact.ddd_twofactorenabled ?? false,
                SecurityStamp     = contact.ddd_securitystamp,
                PhoneNumberConfirmed = contact.ddd_phonenumberconfirmed ?? false

            };
        }

        public static Contact ToContact<TUser>(this TUser user) where TUser : IdentityUser<string>, new()
        {
            if (user == null) return null;
            return new Contact()
            {
                Id                       = new Guid(user.Id),
                EMailAddress1            = user.Email,
                MobilePhone              = user.PhoneNumber,
                ddd_username             = user.UserName,
                ddd_accessfailedcount    = user.AccessFailedCount,
                ddd_lockoutenabled       = user.LockoutEnabled,
                ddd_emailconfirmed       = user.EmailConfirmed,
                ddd_lockoutenddate       = user.LockoutEndDateUtc,
                ddd_passwordhash         = user.PasswordHash,
                ddd_phonenumberconfirmed = user.PhoneNumberConfirmed,
                ddd_securitystamp        = user.SecurityStamp,
                ddd_twofactorenabled     = user.TwoFactorEnabled,
            };
        }
    }
}
