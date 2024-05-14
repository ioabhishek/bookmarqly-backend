/*
  Warnings:

  - You are about to drop the column `collectionDescription` on the `Collection` table. All the data in the column will be lost.
  - You are about to drop the column `collectionName` on the `Collection` table. All the data in the column will be lost.
  - You are about to drop the column `collectionPrivacy` on the `Collection` table. All the data in the column will be lost.
  - You are about to drop the column `collectionThumbnail` on the `Collection` table. All the data in the column will be lost.
  - Added the required column `description` to the `Collection` table without a default value. This is not possible if the table is not empty.
  - Added the required column `isPublic` to the `Collection` table without a default value. This is not possible if the table is not empty.
  - Added the required column `title` to the `Collection` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Collection" DROP COLUMN "collectionDescription",
DROP COLUMN "collectionName",
DROP COLUMN "collectionPrivacy",
DROP COLUMN "collectionThumbnail",
ADD COLUMN     "description" TEXT NOT NULL,
ADD COLUMN     "isPublic" TEXT NOT NULL,
ADD COLUMN     "thumbnail" TEXT,
ADD COLUMN     "title" TEXT NOT NULL;
