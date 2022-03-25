using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using System.Text;
using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Configure the Authentication

// Set up the signingKey for HS256
// Base64 signingKey
//SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Convert.FromBase64String("[Base 64 string of 256 bits]"));

// Short String signingKey (Not advised). Note manually padding to 256 bits if it is a short key, as the SymmetricSignatureProvider does not do the HMACSHA256 RFC2104 padding for you.
SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("secret".PadRight((256/8), '\0')));

// Long String signingKey. Note manually SHA256 of the key, as the SymmetricSignatureProvider does not do the HMACSHA256 RFC2104 hash to shorten the key for you.
/*
byte[] shaBytes;
using (SHA256 shaHash = SHA256.Create()) {
    shaBytes = shaHash.ComputeHash(Encoding.ASCII.GetBytes("SuperLongAndSecretKeyThatNobodyWillGuess"));
}
SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("SuperLongAndSecretKeyThatNobodyWillGuess"));
*/

builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters
    {
        /*
            Sample:
            {
                "alg": "HS256",
                "typ": "JWT"
            }.{
                "sub": "1234567890",
                "name": "John Doe",
                "iat": 1516239022,
                "exp": 1916239022,
                "iss": "AuthorizedIssuer",
                "aud": "AuthenticatedAPI"
            }

            Paste into Swagger Authorize dialogue as:
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MTYyMzkwMjIsImlzcyI6IkF1dGhvcml6ZWRJc3N1ZXIiLCJhdWQiOiJBdXRoZW50aWNhdGVkQVBJIn0.AOAUd9y_efAdahJZrQXTnweZ-tiUGjBQ1YvvZFpYyck"
        */
        ValidateAudience = true,
        ValidateIssuer = true,
        ValidIssuer = "https://localhost:7046/",
        ValidAudience = "https://localhost:7046/",
        RequireSignedTokens = true,
        IssuerSigningKey = signingKey,
        ValidateLifetime = true
    };
});

builder.Services.AddAuthorization(auth =>
            {
                auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser().Build());
            });

// Define a relaxation of default browser CORS policy
/* 
var CorsPolicy = "_CorsPolicy";
builder.Services.AddCors(options => {
    options.AddPolicy(name: CorsPolicy, builder => {
        builder
            .WithOrigins("http://example.com", "http://www.contoso.com")
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});
*/

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthenticatedAPI", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme() {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme."

    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                new string[] {}
        }
    });
});

var app = builder.Build();

// Enable Auth
app.UseAuthentication();
app.UseAuthorization();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Enable Cors
// app.UseCors(CorsPolicy);

app.UseAuthorization();

app.MapControllers();

app.Run();
