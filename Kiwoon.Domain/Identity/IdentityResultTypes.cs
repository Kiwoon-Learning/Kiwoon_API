using Microsoft.AspNetCore.Identity;

namespace Kiwoon.Domain.Identity
{
    public static class IdentityResultTypes
    {
        public static IdentityResult IdNotFound => IdentityResult.Failed(new IdentityError
        {
            Code = "IdNotFound",
            Description = "Id could not be found"
        });
        public static IdentityResult EmailNotFound => IdentityResult.Failed(new IdentityError
        {
            Code = "EmailNotFound",
            Description = "Email from token not found"
        });
        public static IdentityResult UserNotFound => IdentityResult.Failed(new IdentityError
        {
            Code = "UserNotFound",
            Description = "User could not be found"
        });
        public static IdentityResult BadUser => IdentityResult.Failed(new IdentityError
        {
            Code = "BadUser",
            Description = "Incorrect or invalid user"
        });
        public static IdentityResult BadToken => IdentityResult.Failed(new IdentityError
        {
            Code = "BadToken",
            Description = "Invalid token"
        });
        public static IdentityResult NotAJwtToken => IdentityResult.Failed(new IdentityError
        {
            Code = "NotAJwtToken", 
            Description = "Token is not a JWT token"
        });
        public static IdentityResult BadTokenPurpose => IdentityResult.Failed(new IdentityError
        {
            Code = "BadPurpose", 
            Description = "Incorrect JWT purpose"
        });
        public static IdentityResult BadEmail =>  IdentityResult.Failed(new IdentityError
        {
            Code = "BadEmail",
            Description = "Email does not match"
        });
        public static IdentityResult BadNewEmail => IdentityResult.Failed(new IdentityError
        {
            Code = "BadNewEmail",
            Description = "Email is already taken"
        });
        public static IdentityResult NotAnEmail => IdentityResult.Failed(new IdentityError
        {
            Code = "NotAnEmail",
            Description = "Not a valid email address"
        });
        public static IdentityResult BadPassword => IdentityResult.Failed(new IdentityError
        {
            Code = "BadPassword",
            Description = "Incorrect password"
        });
        public static IdentityResult SamePassword => IdentityResult.Failed(new IdentityError
        {
            Code = "SamePassword",
            Description = "Both passwords cannot be the same"
        });
        public static IdentityResult NoHash => IdentityResult.Failed(new IdentityError
        {
            Code = "NoHash", 
            Description = "Could not find hash from token"
        });
        public static IdentityResult BadHash => IdentityResult.Failed(new IdentityError
        {
            Code = "BadHash",
            Description = "Provided hash does not match correctly"
        });
    }
}
