-- CreateTable
CREATE TABLE "Collection" (
    "id" TEXT NOT NULL,
    "collectionName" TEXT NOT NULL,
    "collectionDescription" TEXT NOT NULL,
    "collectionThumbnail" TEXT,
    "collectionPrivacy" TEXT NOT NULL,
    "userId" TEXT,

    CONSTRAINT "Collection_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Collection" ADD CONSTRAINT "Collection_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
