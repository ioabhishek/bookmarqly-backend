/*
  Warnings:

  - Changed the type of `isPublic` on the `Collection` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "Collection" DROP COLUMN "isPublic",
ADD COLUMN     "isPublic" BOOLEAN NOT NULL;
