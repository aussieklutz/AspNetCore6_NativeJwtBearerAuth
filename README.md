# AspNetCore6_NativeJwtBearerAuth

Demonstrates a basic AspNetCore 6.0 WebAPI with Bearer Auth implemented purely using the native handlers

Other examples I could find implemented this functionality by creating a custom auth handler. This uses the native JwtBearer handlers.

Also implements HS256. Other examples I could find implement RS256.

## Add Package

~~~
dotnet add package Microsoft.AspNetCore.Cors
dotnet add package Microsoft.AspNetCore.Authorization
dotnet add package Microsoft.AspNetCore.Authentication
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
~~~

Note: I am unsure why, but adding the Microsoft.IdentityModel.Tokens package breaks this. 
I think there are some components implemented in both with a name collision