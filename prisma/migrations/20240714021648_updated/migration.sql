-- AlterTable
ALTER TABLE "Bookmark" ADD COLUMN     "ogDescription" TEXT,
ADD COLUMN     "ogImage" TEXT,
ADD COLUMN     "ogTitle" TEXT,
ALTER COLUMN "title" DROP NOT NULL;
