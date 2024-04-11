-- AlterTable
ALTER TABLE "User" ADD COLUMN     "forgotPasswordExpiry" TEXT,
ADD COLUMN     "forgotPasswordToken" TEXT;
