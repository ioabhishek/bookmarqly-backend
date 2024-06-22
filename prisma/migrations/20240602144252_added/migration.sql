-- AlterTable
ALTER TABLE "Collection" ADD COLUMN "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Set the default value for existing rows
UPDATE "Collection" SET "updatedAt" = CURRENT_TIMESTAMP;

-- Remove the default value so Prisma can manage it
ALTER TABLE "Collection" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "User" ADD COLUMN "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
                   ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Set the default value for existing rows
UPDATE "User" SET "updatedAt" = CURRENT_TIMESTAMP;

-- Remove the default value so Prisma can manage it
ALTER TABLE "User" ALTER COLUMN "updatedAt" DROP DEFAULT;