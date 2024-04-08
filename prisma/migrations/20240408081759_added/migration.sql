-- AlterTable
ALTER TABLE "User" ADD COLUMN     "emailVerificationExpiry" TEXT,
ADD COLUMN     "emailVerificationToken" TEXT;
