# This dockerfile builds and runs the UnimerseServer application on a Raspberry Pi (ARM64 architecture).

# Stage 1: build on the Pi itself
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy project files first to leverage Docker layer caching
COPY UnimerseLib/UnimerseLib.csproj ./UnimerseLib/
COPY UnimerseServer/UnimerseServer.csproj ./UnimerseServer/

# Restore NuGet packages (cached if no changes)
RUN dotnet restore ./UnimerseServer/UnimerseServer.csproj

# Copy source code
COPY UnimerseLib ./UnimerseLib
COPY UnimerseServer ./UnimerseServer

# Publish for the Pi's ARM64 architecture
RUN dotnet publish ./UnimerseServer/UnimerseServer.csproj -c Release -r linux-arm64 --self-contained false -o /app

# Stage 2: minimal runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app

# Copy the published app from the build stage
COPY --from=build /app .

# Copy static webroot files
COPY UnimerseServer/staticwebroot ./staticwebroot


# Expose server port
EXPOSE 5000

# Environment variables for consistent builds
ENV UNIMERSE_MASTER_PASSWORD="41uE8vgi2Dn0droxAtqATGvVB6RdwGZW" # Don't get excited, this is just a default environment variable for testing
.																# All users should change it on first run

# Run the server
ENTRYPOINT ["dotnet", "UnimerseServer.dll"]
