﻿using System.Security.Claims;

namespace SharedModels.Domain.Identity
{
    public class ApplicationClaim
    {
        public ApplicationClaim()
        {
            
        }
#nullable enable
        public ApplicationClaim(Claim claim)
        {
            Type = claim.Type;
            Value = claim.Value;
            ValueType = claim.ValueType;
            Issuer = claim.Issuer;
            OriginalIssuer = claim.OriginalIssuer;
        }
        public string Type { get; set; }
        public string Value { get; set; }
        public string? ValueType { get; set; }
        public string? Issuer { get; set; }
        public string? OriginalIssuer { get; set; }
        public Claim ToClaim() => new(Type, Value, ValueType, Issuer, OriginalIssuer);
    }
}
