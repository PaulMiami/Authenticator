using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;
using PaulMiami.AspNetCore.Authentication.Authenticator;

namespace TestWebAppIdentity.Data.Migrations
{
    public partial class Authenticator : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte>(
                name: "AuthenticatorHashAlgorithm",
                table: "AspNetUsers",
                nullable: false,
                defaultValue: HashAlgorithmType.SHA1);

            migrationBuilder.AddColumn<byte>(
                name: "AuthenticatorNumberOfDigits",
                table: "AspNetUsers",
                nullable: false,
                defaultValue: (byte)0);

            migrationBuilder.AddColumn<byte>(
                name: "AuthenticatorPeriodInSeconds",
                table: "AspNetUsers",
                nullable: false,
                defaultValue: (byte)0);

            migrationBuilder.AddColumn<string>(
                name: "AuthenticatorSecretEncrypted",
                table: "AspNetUsers",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AuthenticatorHashAlgorithm",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "AuthenticatorNumberOfDigits",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "AuthenticatorPeriodInSeconds",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "AuthenticatorSecretEncrypted",
                table: "AspNetUsers");
        }
    }
}
