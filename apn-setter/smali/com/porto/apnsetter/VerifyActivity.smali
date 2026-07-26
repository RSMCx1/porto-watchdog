.class public Lcom/porto/apnsetter/VerifyActivity;
.super Landroid/app/Activity;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method


# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 8

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    # v0 = getContentResolver()
    invoke-virtual {p0}, Landroid/app/Activity;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    # v1 = Uri.parse("content://telephony/carriers/preferapn")
    const-string v6, "content://telephony/carriers/preferapn"

    invoke-static {v6}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v1

    # v2 = new String[]{"name","apn","protocol","roaming_protocol"}
    const/4 v6, 0x4

    new-array v2, v6, [Ljava/lang/String;

    const/4 v6, 0x0

    const-string v7, "name"

    aput-object v7, v2, v6

    const/4 v6, 0x1

    const-string v7, "apn"

    aput-object v7, v2, v6

    const/4 v6, 0x2

    const-string v7, "protocol"

    aput-object v7, v2, v6

    const/4 v6, 0x3

    const-string v7, "roaming_protocol"

    aput-object v7, v2, v6

    # nulls for the range call (must be consecutive with v0..v2)
    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    # cursor = query(uri, projection, null, null, null)   -- 6 regs -> /range
    invoke-virtual/range {v0 .. v5}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v0

    if-eqz v0, :end

    invoke-interface {v0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v1

    if-eqz v1, :closeend

    const-string v5, "ApnVerify"

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-static {v5, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    const/4 v1, 0x1

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-static {v5, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    const/4 v1, 0x2

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-static {v5, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    const/4 v1, 0x3

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-static {v5, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :closeend
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    :end
    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    return-void
.end method
