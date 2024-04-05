/*
  Warnings:

  - Added the required column `isEmailVerified` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `loginType` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" ADD COLUMN     "isEmailVerified" BOOLEAN NOT NULL,
ADD COLUMN     "loginType" TEXT NOT NULL;
