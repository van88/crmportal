// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;
using Task = System.Threading.Tasks.Task;

namespace CrmStore
{
    /// <summary>
    ///     Crm SDK user store implementation that supports IUserStore, IUserLoginStore, IUserClaimStore and
    ///     IUserRoleStore
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TRole"></typeparam>
    /// <typeparam name="Guid"></typeparam>
    ///// <typeparam name="TUserLogin"></typeparam>
    ///// <typeparam name="TUserRole"></typeparam>
    ///// <typeparam name="TUserClaim"></typeparam>
    public class CrmUserStore<TUser> :
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        //IQueryableUserStore<TUser, string>,
        IUserEmailStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IUserTwoFactorStore<TUser, string>,
        IUserLockoutStore<TUser, string> ,
        IUserStore<TUser>
        where TUser : IdentityUser, new()
        //where TUserLogin : IdentityUserLogin<Guid>, new()
        //where TUserRole : IdentityUserRole<Guid>, new()
        //where TUserClaim : IdentityUserClaim<Guid>, new()
    {
        //private readonly EntityStore<TUserLogin> _logins;
        //private readonly EntityStore<TRole> _roleStore;
        //private readonly EntityStore<TUserClaim> _userClaims;
        //private readonly EntityStore<TUserRole> _userRoles;
        //private EntityStore<TUser> _userStore;

        private bool _disposed;
        
        /// <summary>
        ///     Constructor which takes a db context and wires up the stores with default instances using the context
        /// </summary>
        /// <param name="context"></param>
        public CrmUserStore(CrmServiceContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            Context = context;
            //_userStore = new EntityStore<TUser>(context);
            //_roleStore = new EntityStore<TRole>(context);
            //_logins = context.ContactSet;
            //_userClaims = Context.Set<TUserClaim>();
            //_userRoles = Context.Set<TUserRole>();
        }

        /// <summary>
        ///     Context for the store
        /// </summary>
        private CrmServiceContext Context { get;  set; }

        /// <summary>
        ///     If true will call dispose on the DbContext during Dispose
        /// </summary>
        public bool DisposeContext { get; set; }
        
        /// <summary>
        ///     Return the claims for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            //await EnsureClaimsLoaded(user);
            return user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
        }

        /// <summary>
        ///     Add a claim to a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public virtual Task AddClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            
            Context.AddObject(new ddd_userclaim()
            {
                ddd_contactid = new EntityReference(Contact.EntityLogicalName, new Guid(user.Id)),
                ddd_claimtype = claim.Type,
                ddd_claimvalue = claim.Value
            });
            //_userClaims.Add(new IdentityUserClaim<Guid>() { UserId = user.Id, ClaimType = claim.Type, ClaimValue = claim.Value });
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Remove a claim from a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public virtual async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var userClaim = Context.ddd_userclaimSet.Where(x => x.ddd_contactid.Id == new Guid(user.Id)
                                                                && x.ddd_claimtype == claim.Type
                                                                && x.ddd_claimvalue == claim.Value);

            if (userClaim.Any())
            {
                Context.DeleteObject(userClaim.First());
            }
            //IEnumerable<TUserClaim> claims;
            //var claimValue = claim.Value;
            //var claimType = claim.Type;
            //if (AreClaimsLoaded(user))
            //{
            //    claims = user.Claims.Where(uc => uc.ClaimValue == claimValue && uc.ClaimType == claimType).ToList();
            //}
            //else
            //{
            //    var userId = user.Id;
            //    claims = await _userClaims.Where(uc => uc.ClaimValue == claimValue && uc.ClaimType == claimType && uc.UserId.Equals(userId)).ToListAsync();
            //}
            //foreach (var c in claims)
            //{
            //    _userClaims.Remove(c);
            //}
        }

        /// <summary>
        ///     Returns whether the user email is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.EmailConfirmed);
        }

        /// <summary>
        ///     Set IsConfirmed on the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="confirmed"></param>
        /// <returns></returns>
        public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Set the user email
        /// </summary>
        /// <param name="user"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        public virtual Task SetEmailAsync(TUser user, string email)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.Email = email;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Get the user's email
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.Email);
        }

        /// <summary>
        ///     Find a user by email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public virtual Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();

            var contact = Context.ContactSet.FirstOrDefault(
                x => x.EMailAddress1 == email);

            if (contact != null)
            {
                return Task.FromResult(contact.ToIdentityUser<TUser>());
            }
            //return GetUserAggregateAsync(u => u.Email.ToUpper() == email.ToUpper());

            return Task.FromResult((TUser)null);
        }

        /// <summary>
        ///     Returns the DateTimeOffset that represents the end of a user's lockout, any time in the past should be considered
        ///     not locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return
                Task.FromResult(user.LockoutEndDateUtc.HasValue
                    ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
                    : new DateTimeOffset());
        }

        /// <summary>
        ///     Locks a user out until the specified end date (set to a past date, to unlock a user)
        /// </summary>
        /// <param name="user"></param>
        /// <param name="lockoutEnd"></param>
        /// <returns></returns>
        public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.LockoutEndDateUtc = lockoutEnd == DateTimeOffset.MinValue ? (DateTime?)null : lockoutEnd.UtcDateTime;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Used to record when an attempt to access the user has failed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        ///     Used to reset the account access count, typically after the account is successfully accessed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task ResetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Returns the current number of failed access attempts.  This number usually will be reset whenever the password is
        ///     verified or the account is locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<int> GetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        ///     Returns whether the user can be locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.LockoutEnabled);
        }

        /// <summary>
        ///     Sets whether the user can be locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Find a user by id
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<TUser> FindByIdAsync(Guid userId)
        {
            ThrowIfDisposed();
            return FindUserById(userId);
        }

        /// <summary>
        ///     Find a user by name
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public virtual async Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            return Context.ContactSet.FirstOrDefault(x => x.ddd_username == userName).ToIdentityUser<TUser>(); ;
        }

        /// <summary>
        ///     Insert an entity
        /// </summary>
        /// <param name="user"></param>
        public virtual async Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            Context.AddObject(user.ToContact());
            Context.SaveChanges();
            //_userStore.Create(user);
            //await SaveChanges();
        }

        /// <summary>
        ///     Mark an entity for deletion
        /// </summary>
        /// <param name="user"></param>
        public virtual async Task DeleteAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            Context.DeleteObject(user.ToContact());
            Context.SaveChanges();
            //_userStore.Delete(user);
            //await SaveChanges();
        }

        /// <summary>
        ///     Update an entity
        /// </summary>
        /// <param name="user"></param>
        public virtual async Task UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            Context.UpdateObject(user.ToContact());
            Context.SaveChanges();
            //_userStore.Update(user);
            //await SaveChanges();
        }

        /// <summary>
        ///     Dispose the store
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // IUserLogin implementation

        /// <summary>
        ///     Returns the user associated with this login
        /// </summary>
        /// <returns></returns>
        public virtual async Task<TUser> FindAsync(UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }
            var provider = login.LoginProvider;
            var key = login.ProviderKey;

            var userLogin =
                Context.ddd_userloginSet.FirstOrDefault(l => l.ddd_loginprovider == provider && l.ddd_providerkey == key);
            if (userLogin != null)
            {
                var userId = userLogin.ddd_userid.Id;
                return FindUserById(userId);
            }
            return null;
        }

        private TUser FindUserById(Guid id)
        {
            return Context.ContactSet.FirstOrDefault(x => x.Id == id).ToIdentityUser<TUser>();
        }

        /// <summary>
        ///     Add a login to the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            Context.AddObject(new ddd_userlogin()
            {
                ddd_userid = new EntityReference(Contact.EntityLogicalName, new Guid(user.Id)),
                ddd_providerkey = login.ProviderKey,
                ddd_loginprovider = login.LoginProvider
            });

            return Task.FromResult(0);
        }

        /// <summary>
        ///     Remove a login from a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public virtual async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            var entry = Context.ddd_userloginSet.FirstOrDefault(
                ul => ul.ddd_loginprovider == login.LoginProvider 
                && ul.ddd_providerkey == login.ProviderKey && ul.ddd_userid.Id == new Guid(user.Id));
            
            if (entry != null)
            {
                Context.DeleteObject(entry);
                Context.SaveChanges();
            }
        }

        /// <summary>
        ///     Get the logins for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var logins = Context.ddd_userloginSet.Where(x => x.ddd_userid.Id == user.IdGuid);

            return logins.Select(x => new UserLoginInfo(x.ddd_loginprovider, x.ddd_providerkey)).ToList();
            //await EnsureLoginsLoaded(user);
            //return user.Logins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey)).ToList();
        }

        /// <summary>
        ///     Set the password hash for a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="passwordHash"></param>
        /// <returns></returns>
        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Get the password hash for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.PasswordHash);
        }

        /// <summary>
        ///     Returns true if the user has a password set
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        /// <summary>
        ///     Set the user's phone number
        /// </summary>
        /// <param name="user"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Get a user's phone number
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<string> GetPhoneNumberAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>
        ///     Returns whether the user phoneNumber is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <summary>
        ///     Set PhoneNumberConfirmed on the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="confirmed"></param>
        /// <returns></returns>
        public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Add a user to a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public virtual async Task AddToRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException("", nameof(roleName));
            }
            var roleEntity = Context.ddd_userroleSet.SingleOrDefault(x => roleName == x.ddd_name);
            var contact = Context.ContactSet.SingleOrDefault(x => x.Id == user.IdGuid);
            if (roleEntity == null || contact == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, $"{roleName} or {user.Id} does not exist"));
            }
            
            Context.AddLink(contact, new Relationship("//TODO"), roleEntity);
            Context.SaveChanges();
        }

        /// <summary>
        ///     Remove a user from a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public virtual async Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(nameof(roleName));
            }
            var roleEntity = Context.ddd_userroleSet.SingleOrDefault(x => roleName == x.ddd_name);
            var contact = Context.ContactSet.SingleOrDefault(x => x.Id == user.IdGuid);
            if (roleEntity == null || contact == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, $"{roleName} or {user.Id} does not exist"));
            }

            Context.AddLink(contact, new Relationship("//TODO"), roleEntity);
            Context.SaveChanges();
            //var roleEntity = await _roleStore.DbEntitySet.SingleOrDefaultAsync(r => r.Name.ToUpper() == roleName.ToUpper());
            //if (roleEntity != null)
            //{
            //    var roleId = roleEntity.Id;
            //    var userId = user.Id;
            //    var userRole = await _userRoles.FirstOrDefaultAsync(r => roleId.Equals(r.RoleId) && r.UserId.Equals(userId));
            //    if (userRole != null)
            //    {
            //        _userRoles.Remove(userRole);
            //    }
            //}
        }

        /// <summary>
        ///     Get the names of the roles a user is a member of
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<IList<string>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var userId = user.IdGuid;
            var contact = Context.ContactSet.SingleOrDefault(x => x.Id == userId);
            var roles = contact?.ddd_contact_ddd_userrole?.Select(x => x.ddd_name).ToList();
            //var query = from userRole in _userRoles
            //            where userRole.UserId.Equals(userId)
            //            join role in _roleStore.DbEntitySet on userRole.RoleId equals role.Id
            //            select role.Name;
            //return await query.ToListAsync();

            return roles ?? new List<string>();
        }

        /// <summary>
        ///     Returns true if the user is in the named role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public virtual async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(nameof(roleName));
            }
            var userId = user.IdGuid;
            var contact = Context.ContactSet.SingleOrDefault(x => x.Id == userId);
            var isInRole = contact?.ddd_contact_ddd_userrole?.Any(x => roleName == x.ddd_name);
            //var query = from userRole in _userRoles
            //            where userRole.UserId.Equals(userId)
            //            join role in _roleStore.DbEntitySet on userRole.RoleId equals role.Id
            //            select role.Name;
            //return await query.ToListAsync();
            
            return isInRole ?? false;
        }

        /// <summary>
        ///     Set the security stamp for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="stamp"></param>
        /// <returns></returns>
        public virtual Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Get the security stamp for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.SecurityStamp);
        }

        /// <summary>
        ///     Set whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Gets whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.TwoFactorEnabled);
        }
        
        //private bool AreClaimsLoaded(TUser user)
        //{
        //    return Context.Entry(user).Collection(u => u.Claims).IsLoaded;
        //}

        //private async Task EnsureClaimsLoaded(TUser user)
        //{
        //    if (!AreClaimsLoaded(user))
        //    {
        //        var userId = user.Id;
        //        await _userClaims.Where(uc => uc.UserId.Equals(userId)).LoadAsync();
        //        Context.Entry(user).Collection(u => u.Claims).IsLoaded = true;
        //    }
        //}

        //private async Task EnsureRolesLoaded(TUser user)
        //{
        //    if (!Context.Entry(user).Collection(u => u.Roles).IsLoaded)
        //    {
        //        var userId = user.Id;
        //        await _userRoles.Where(uc => uc.UserId.Equals(userId)).LoadAsync();
        //        Context.Entry(user).Collection(u => u.Roles).IsLoaded = true;
        //    }
        //}

        //private bool AreLoginsLoaded(TUser user)
        //{
        //    return Context.Entry(user).Collection(u => u.Logins).IsLoaded;
        //}

        //private async Task EnsureLoginsLoaded(TUser user)
        //{
        //    if (!AreLoginsLoaded(user))
        //    {
        //        var userId = user.Id;
        //        await _logins.Where(uc => uc.UserId.Equals(userId)).LoadAsync();
        //        Context.Entry(user).Collection(u => u.Logins).IsLoaded = true;
        //    }
        //}

        ///// <summary>
        ///// Used to attach child entities to the User aggregate, i.e. Roles, Logins, and Claims
        ///// </summary>
        ///// <param name="filter"></param>
        ///// <returns></returns>
        //protected virtual async Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
        //{
        //    Guid id;
        //    TUser user;
        //    if (FindByIdFilterParser.TryMatchAndGetId(filter, out id))
        //    {
        //        user = await _userStore.GetByIdAsync(id);
        //    }
        //    else
        //    {
        //        user = await Users.FirstOrDefaultAsync(filter);
        //    }
        //    if (user != null)
        //    {
        //        await EnsureClaimsLoaded(user);
        //        await EnsureLoginsLoaded(user);
        //        await EnsureRolesLoaded(user);
        //    }
        //    return user;
        //}

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        ///     If disposing, calls dispose on the Context.  Always nulls out the Context
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (DisposeContext && disposing && Context != null)
            {
                Context.Dispose();
            }
            _disposed = true;
            Context = null;
        }

        public Task<TUser> FindByIdAsync(string userId)
        {
            var contact = Context.ContactSet.FirstOrDefault(x => x.Id == new Guid(userId));

            return Task.FromResult(contact.ToIdentityUser<TUser>());
        }
    }

    public interface IEntityMapping<TDomain, TEntity> where TDomain: new() where TEntity: Entity
    {
        TEntity CreateCrmEntity(TDomain domain);
        TDomain CreateDomainEntity(TEntity entity);
    }
    

}