namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// SCERT (SCE Real-Time) transport layer message type IDs.
/// These are the raw packet type bytes on the wire.
/// </summary>
public enum RT_MSG_TYPE : byte
{
    RT_MSG_CLIENT_CONNECT_TCP                = 0x00,
    RT_MSG_CLIENT_DISCONNECT                 = 0x01,
    RT_MSG_CLIENT_APP_BROADCAST              = 0x02,
    RT_MSG_CLIENT_APP_SINGLE                 = 0x03,
    RT_MSG_CLIENT_APP_LIST                   = 0x04,
    RT_MSG_CLIENT_ECHO                       = 0x05,
    RT_MSG_SERVER_CONNECT_REJECT             = 0x06,
    RT_MSG_SERVER_CONNECT_ACCEPT_TCP         = 0x07,
    RT_MSG_SERVER_CONNECT_NOTIFY             = 0x08,
    RT_MSG_SERVER_DISCONNECT_NOTIFY          = 0x09,
    RT_MSG_SERVER_APP                        = 0x0A,
    RT_MSG_CLIENT_APP_TOSERVER               = 0x0B,
    RT_MSG_UDP_APP                           = 0x0C,
    RT_MSG_CLIENT_SET_RECV_FLAG              = 0x0D,
    RT_MSG_CLIENT_SET_AGG_TIME               = 0x0E,
    RT_MSG_CLIENT_FLUSH_ALL                  = 0x0F,
    RT_MSG_CLIENT_FLUSH_SINGLE               = 0x10,
    RT_MSG_SERVER_FORCED_DISCONNECT          = 0x11,
    RT_MSG_CLIENT_CRYPTKEY_PUBLIC            = 0x12,
    RT_MSG_SERVER_CRYPTKEY_PEER              = 0x13,
    RT_MSG_SERVER_CRYPTKEY_GAME              = 0x14,
    RT_MSG_CLIENT_CONNECT_TCP_AUX_UDP        = 0x15,
    RT_MSG_CLIENT_CONNECT_AUX_UDP            = 0x16,
    RT_MSG_CLIENT_CONNECT_READY_AUX_UDP      = 0x17,
    RT_MSG_SERVER_INFO_AUX_UDP               = 0x18,
    RT_MSG_SERVER_CONNECT_ACCEPT_AUX_UDP     = 0x19,
    RT_MSG_SERVER_CONNECT_COMPLETE           = 0x1A,
    RT_MSG_CLIENT_CRYPTKEY_PEER              = 0x1B,
    RT_MSG_SERVER_SYSTEM_MESSAGE             = 0x1C,
    RT_MSG_SERVER_CHEAT_QUERY                = 0x1D,
    RT_MSG_SERVER_MEMORY_POKE                = 0x1E,
    RT_MSG_SERVER_ECHO                       = 0x1F,
    RT_MSG_CLIENT_DISCONNECT_WITH_REASON     = 0x20,
    RT_MSG_CLIENT_CONNECT_READY_TCP          = 0x21,
    RT_MSG_SERVER_CONNECT_REQUIRE            = 0x22,
    RT_MSG_CLIENT_CONNECT_READY_REQUIRE      = 0x23,
    RT_MSG_CLIENT_HELLO                      = 0x24,
    RT_MSG_SERVER_HELLO                      = 0x25,
    RT_MSG_SERVER_STARTUP_INFO_NOTIFY        = 0x26,
    RT_MSG_CLIENT_PEER_QUERY                 = 0x27,
    RT_MSG_SERVER_PEER_QUERY_NOTIFY          = 0x28,
    RT_MSG_CLIENT_PEER_QUERY_LIST            = 0x29,
    RT_MSG_SERVER_PEER_QUERY_LIST_NOTIFY     = 0x2A,
    RT_MSG_CLIENT_WALLCLOCK_QUERY            = 0x2B,
    RT_MSG_SERVER_WALLCLOCK_QUERY_NOTIFY     = 0x2C,
    RT_MSG_CLIENT_TIMEBASE_QUERY             = 0x2D,
    RT_MSG_SERVER_TIMEBASE_QUERY_NOTIFY      = 0x2E,
    RT_MSG_CLIENT_TOKEN_MESSAGE              = 0x2F,
    RT_MSG_SERVER_TOKEN_MESSAGE              = 0x30,
    RT_MSG_CLIENT_SYSTEM_MESSAGE             = 0x31,
    RT_MSG_CLIENT_APP_BROADCAST_QOS         = 0x32,
    RT_MSG_CLIENT_APP_SINGLE_QOS            = 0x33,
    RT_MSG_CLIENT_APP_LIST_QOS              = 0x34,
    RT_MSG_CLIENT_MAX_MSGLEN                = 0x35,
    RT_MSG_SERVER_MAX_MSGLEN                = 0x36,
    RT_MSG_CLIENT_MULTI_APP_TOSERVER        = 0x3B,
    RT_MSG_SERVER_MULTI_APP_TOCLIENT        = 0x3C,
}

/// <summary>
/// Medius application-layer message class (first byte of app payload).
/// </summary>
public enum NetMessageClass : byte
{
    MessageClassDME             = 0,
    MessageClassLobby           = 1,
    MessageClassApplication     = 2,
    MessageClassLobbyReport     = 3,
    MessageClassLobbyExt        = 4,
    MessageClassLobbyAuth       = 5,
}

/// <summary>
/// Medius Lobby message type IDs (MessageClassLobby).
/// </summary>
public enum MediusLobbyMessageId : byte
{
    WorldReport0                    = 0x00,
    PlayerReport                    = 0x01,
    EndGameReport                   = 0x02,
    SessionBegin                    = 0x03,
    SessionBeginResponse            = 0x04,
    SessionEnd                      = 0x05,
    SessionEndResponse              = 0x06,
    AccountLogin                    = 0x07,
    AccountLoginResponse            = 0x08,
    AccountRegistration             = 0x09,
    AccountRegistrationResponse     = 0x0A,
    AccountGetProfile               = 0x0B,
    AccountGetProfileResponse       = 0x0C,
    AccountUpdateProfile            = 0x0D,
    AccountUpdateProfileResponse    = 0x0E,
    AccountUpdatePassword           = 0x0F,
    AccountUpdateStats              = 0x11,
    AccountUpdateStatsResponse      = 0x12,
    AccountDelete                   = 0x13,
    AccountDeleteResponse           = 0x14,
    AccountLogout                   = 0x15,
    AccountLogoutResponse           = 0x16,
    AccountGetID                    = 0x17,
    AccountGetIDResponse            = 0x18,
    AnonymousLogin                  = 0x19,
    AnonymousLoginResponse          = 0x1A,
    GetMyIP                         = 0x1B,
    GetMyIPResponse                 = 0x1C,
    CreateGameRequest0              = 0x1D,
    CreateGameResponse              = 0x1E,
    CreateGameOnSelf                = 0x1F,
    CreateGameOnSelfResponse        = 0x20,
    CreateChannelRequest0           = 0x21,
    CreateChannelResponse           = 0x22,
    JoinGameRequest0                = 0x23,
    JoinGameResponse                = 0x24,
    JoinChannel                     = 0x25,
    JoinChannelResponse             = 0x26,
    JoinChannelFwd                  = 0x27,
    JoinChannelFwdResponse          = 0x28,
    GameList                        = 0x29,
    GameListResponse                = 0x2A,
    ChannelList                     = 0x2B,
    ChannelListResponse             = 0x2C,
    LobbyWorldPlayerList            = 0x2D,
    LobbyWorldPlayerListResponse    = 0x2E,
    GameWorldPlayerList             = 0x2F,
    GameWorldPlayerListResponse     = 0x30,
    PlayerInfo                      = 0x31,
    PlayerInfoResponse              = 0x32,
    GameInfo0                       = 0x33,
    GameInfoResponse0               = 0x34,
    ChannelInfo                     = 0x35,
    ChannelInfoResponse             = 0x36,
    FindWorldByName                 = 0x37,
    FindWorldByNameResponse         = 0x38,
    FindPlayer                      = 0x39,
    FindPlayerResponse              = 0x3A,
    ChatMessage                     = 0x3B,
    ChatFwdMessage                  = 0x3C,
    GetBuddyList                    = 0x3D,
    GetBuddyListResponse            = 0x3E,
    AddToBuddyList                  = 0x3F,
    AddToBuddyListResponse          = 0x40,
    RemoveFromBuddyList             = 0x41,
    RemoveFromBuddyListResponse     = 0x42,
    Policy                          = 0x47,
    PolicyResponse                  = 0x48,
    UpdateUserState                 = 0x49,
    ErrorMessage                    = 0x4A,
    GetAnnouncements                = 0x4B,
    GetAllAnnouncements             = 0x4C,
    GetAnnouncementsResponse        = 0x4D,
    SetGameListFilter0              = 0x4E,
    SetGameListFilterResponse0      = 0x4F,
    ClearGameListFilter0            = 0x50,
    ClearGameListFilterResponse     = 0x51,
    GetGameListFilter               = 0x52,
    GetGameListFilterResponse0      = 0x53,
    // Note: 0x54–0x8F covered by the clan/ladder/file/location block below.
    // In older Medius versions (PS2 era) 0x62–0x65 were used for different
    // purposes (TicketLogin / GetUniverse).  Those are preserved below for
    // backwards-compatibility with SOCOM II and similar games; in canonical
    // horizon-server Medius the same values are InvitePlayerToClan /
    // CheckMyClanInvitations.
    TicketLogin                     = 0x62,
    TicketLoginResponse             = 0x63,
    GetUniverse                     = 0x64,
    GetUniverseResponse             = 0x65,
    AddToBuddyListConfirmationRequest0          = 0x43,
    AddToBuddyListConfirmationResponse          = 0x44,
    AddToBuddyListFwdConfirmationRequest0       = 0x45,
    AddToBuddyListFwdConfirmationResponse0      = 0x46,
    // clan operations 0x54–0x83
    CreateClan                                  = 0x54,
    CreateClanResponse                          = 0x55,
    DisbandClan                                 = 0x56,
    DisbandClanResponse                         = 0x57,
    GetClanByID                                 = 0x58,
    GetClanByIDResponse                         = 0x59,
    GetClanByName                               = 0x5A,
    GetClanByNameResponse                       = 0x5B,
    TransferClanLeadership                      = 0x5C,
    TransferClanLeadershipResponse              = 0x5D,
    AddPlayerToClan                             = 0x5E,
    AddPlayerToClanResponse                     = 0x5F,
    RemovePlayerFromClan                        = 0x60,
    RemovePlayerFromClanResponse                = 0x61,
    // 0x62–0x65 are reserved for TicketLogin/GetUniverse (PS2 game-specific; see above)
    InvitePlayerToClan                          = 0x62,  // conflicts with TicketLogin in older Medius
    InvitePlayerToClanResponse                  = 0x63,  // conflicts with TicketLoginResponse in older Medius
    CheckMyClanInvitations                      = 0x64,  // conflicts with GetUniverse in older Medius
    CheckMyClanInvitationsResponse              = 0x65,  // conflicts with GetUniverseResponse in older Medius
    RespondToClanInvitation                     = 0x66,
    RespondToClanInvitationResponse             = 0x67,
    RevokeClanInvitation                        = 0x68,
    RevokeClanInvitationResponse                = 0x69,
    RequestClanTeamChallenge                    = 0x6A,
    RequestClanTeamChallengeResponse            = 0x6B,
    GetMyClanMessages                           = 0x6C,
    GetMyClanMessagesResponse                   = 0x6D,
    SendClanMessage                             = 0x6E,
    SendClanMessageResponse                     = 0x6F,
    ModifyClanMessage                           = 0x70,
    ModifyClanMessageResponse                   = 0x71,
    DeleteClanMessage                           = 0x72,
    DeleteClanMessageResponse                   = 0x73,
    RespondToClanTeamChallenge                  = 0x74,
    RespondToClanTeamChallengeResponse          = 0x75,
    RevokeClanTeamChallenge                     = 0x76,
    RevokeClanTeamChallengeResponse             = 0x77,
    GetClanTeamChallengeHistory                 = 0x78,
    GetClanTeamChallengeHistoryResponse         = 0x79,
    GetClanInvitationsSent                      = 0x7A,
    GetClanInvitationsSentResponse              = 0x7B,
    GetMyClans                                  = 0x7C,
    GetMyClansResponse                          = 0x7D,
    GetAllClanMessages                          = 0x7E,
    GetAllClanMessagesResponse                  = 0x7F,
    ConfirmClanTeamChallenge                    = 0x80,
    ConfirmClanTeamChallengeResponse            = 0x81,
    GetClanTeamChallenges                       = 0x82,
    GetClanTeamChallengesResponse               = 0x83,
    UpdateClanStats                             = 0x84,
    UpdateClanStatsResponse                     = 0x85,
    VersionServer                               = 0x86,
    VersionServerResponse                       = 0x87,
    GetWorldSecurityLevel                       = 0x88,
    GetWorldSecurityLevelResponse               = 0x89,
    BanPlayer                                   = 0x8A,
    BanPlayerResponse                           = 0x8B,
    GetLocations                                = 0x8C,
    GetLocationsResponse                        = 0x8D,
    PickLocation                                = 0x8E,
    PickLocationResponse                        = 0x8F,
    GetClanMemberList                           = 0x90,
    GetClanMemberListResponse                   = 0x91,
    LadderPosition                              = 0x92,
    LadderPositionResponse                      = 0x93,
    LadderList                                  = 0x94,
    LadderListResponse                          = 0x95,
    ChatToggle                                  = 0x96,
    ChatToggleResponse                          = 0x97,
    TextFilter                                  = 0x98,
    TextFilterResponse                          = 0x99,
    ServerReassignGameMediusWorldID             = 0x9A,
    GetTotalGames                               = 0x9B,
    GetTotalGamesResponse                       = 0x9C,
    GetTotalChannels                            = 0x9D,
    GetTotalChannelsResponse                    = 0x9E,
    GetLobbyPlayerNames                         = 0x9F,
    GetLobbyPlayerNamesResponse                 = 0xA0,
    GetTotalUsers                               = 0xA1,
    GetTotalUsersResponse                       = 0xA2,
    SetLocalizationParams                       = 0xA3,
    SetLocalizationParamsResponse               = 0xA4,
    // file services 0xA5–0xBF
    FileCreate                                  = 0xA5,
    FileCreateResponse                          = 0xA6,
    FileUpload                                  = 0xA7,
    FileUploadResponse                          = 0xA8,
    FileUploadServerReq                         = 0xA9,
    FileClose                                   = 0xAA,
    FileCloseResponse                           = 0xAB,
    FileDownload                                = 0xAC,
    FileDownloadResponse                        = 0xAD,
    FileDownloadStream                          = 0xAE,
    FileDownloadStreamResponse                  = 0xAF,
    FileDelete                                  = 0xB0,
    FileDeleteResponse                          = 0xB1,
    FileListFiles                               = 0xB2,
    FileListFilesResponse                       = 0xB3,
    FileUpdateAttributes                        = 0xB4,
    FileUpdateAttributesResponse                = 0xB5,
    FileGetAttributes                           = 0xB6,
    FileGetAttributesResponse                   = 0xB7,
    FileUpdateMetaData                          = 0xB8,
    FileUpdateMetaDataResponse                  = 0xB9,
    FileGetMetaData                             = 0xBA,
    FileGetMetaDataResponse                     = 0xBB,
    FileSearchByMetaData                        = 0xBC,
    FileSearchByMetaDataResponse                = 0xBD,
    FileCancelOperation                         = 0xBE,
    FileCancelOperationResponse                 = 0xBF,
    // ignore lists
    GetIgnoreList                               = 0xC0,
    GetIgnoreListResponse                       = 0xC1,
    AddToIgnoreList                             = 0xC2,
    AddToIgnoreListResponse                     = 0xC3,
    RemoveFromIgnoreList                        = 0xC4,
    RemoveFromIgnoreListResponse                = 0xC5,
    SetMessageAsRead                            = 0xC6,
    SetMessageAsReadResponse                    = 0xC7,
    GetUniverseInformation                      = 0xC8,
    UniverseNewsResponse                        = 0xC9,
    UniverseStatusListResponse                  = 0xCA,
    MachineSignaturePost                        = 0xCB,
    // ladder
    LadderPositionFast                          = 0xCC,
    LadderPositionFastResponse                  = 0xCD,
    UpdateLadderStats                           = 0xCE,
    UpdateLadderStatsResponse                   = 0xCF,
    GetLadderStats                              = 0xD0,
    GetLadderStatsResponse                      = 0xD1,
    ClanLadderList                              = 0xD2,
    ClanLadderListResponse                      = 0xD3,
    ClanLadderPosition                          = 0xD4,
    ClanLadderPositionResponse                  = 0xD5,
    GetBuddyList_ExtraInfo                      = 0xD6,
    GetBuddyList_ExtraInfoResponse              = 0xD7,
    GetTotalRankings                            = 0xD8,
    GetTotalRankingsResponse                    = 0xD9,
    GetClanMemberList_ExtraInfo                 = 0xDA,
    GetClanMemberList_ExtraInfoResponse         = 0xDB,
    GetLobbyPlayerNames_ExtraInfo               = 0xDC,
    GetLobbyPlayerNames_ExtraInfoResponse       = 0xDD,
    // billing
    BillingLogin                                = 0xDE,
    BillingLoginResponse                        = 0xDF,
    BillingListRequest                          = 0xE0,
    BillingListResponse                         = 0xE1,
    BillingDetailRequest                        = 0xE2,
    BillingDetailResponse                       = 0xE3,
    PurchaseProductRequest                      = 0xE4,
    PurchaseProductResponse                     = 0xE5,
    BillingInfo                                 = 0xE6,
    BillingInfoResponse                         = 0xE7,
    BillingTunnelRequest                        = 0xE8,
    BillingTunnelResponse                       = 0xE9,
    // extra game/channel lists
    GameList_ExtraInfo0                         = 0xEA,
    GameList_ExtraInfoResponse0                 = 0xEB,
    ChannelList_ExtraInfo0                      = 0xEC,
    ChannelList_ExtraInfoResponse               = 0xED,
    InvitePlayerToClan_ByName                   = 0xEE,
    LadderList_ExtraInfo0                       = 0xEF,
    LadderList_ExtraInfoResponse                = 0xF0,
    LadderPosition_ExtraInfo                    = 0xF1,
    LadderPosition_ExtraInfoResponse            = 0xF2,
    JoinGame                                    = 0xF3,
    CreateGame1                                 = 0xF4,
    UtilAddLobbyWorld                           = 0xF5,
    UtilAddLobbyWorldResponse                   = 0xF6,
    UtilAddGameWorld                            = 0xF7,
    UtilAddGameWorldResponse                    = 0xF8,
    UtilUpdateLobbyWorld                        = 0xF9,
    UtilUpdateLobbyWorldResponse                = 0xFA,
    UtilUpdateGameWorld                         = 0xFB,
    UtilUpdateGameWorldResponse                 = 0xFC,
}

/// <summary>
/// Medius Lobby Extended message type IDs (MessageClassLobbyExt).
/// </summary>
public enum MediusLobbyExtMessageId : byte
{
    CreateChannel1                      = 0x00,
    UtilGetServerVersion                = 0x01,
    UtilGetServerVersionResponse        = 0x02,
    GetUniverse_ExtraInfo               = 0x03,
    UniverseStatusList_ExtraInfoResponse= 0x04,
    AddToBuddyListConfirmation          = 0x05,
    AddToBuddyListFwdConfirmation       = 0x06,
    AddToBuddyListFwdConfirmationResponse = 0x07,
    GetBuddyInvitations                 = 0x08,
    GetBuddyInvitationsResponse         = 0x09,
    DnasSignaturePost                   = 0x0A,
    UpdateLadderStatsWide               = 0x0B,
    UpdateLadderStatsWideResponse       = 0x0C,
    GetLadderStatsWide                  = 0x0D,
    GetLadderStatsWideResponse          = 0x0E,
    LadderList_ExtraInfo                = 0x0F,
    UtilEventMsgHandler                 = 0x10,
    UniverseVariableInformationResponse = 0x11,
    SetLobbyWorldFilter                 = 0x12,
    SetLobbyWorldFilterResponse         = 0x13,
    CreateChannel                       = 0x14,
    ChannelList_ExtraInfo1              = 0x15,
    BinaryMessage                       = 0x16,
    BinaryFwdMessage                    = 0x17,
    PostDebugInfo                       = 0x18,
    PostDebugInfoResponse               = 0x19,
    UpdateClanLadderStatsWide_Delta     = 0x1A,
    UpdateClanLadderStatsWide_DeltaResponse = 0x1B,
    GetLadderStatsWide_wIDArray         = 0x1C,
    GetLadderStatsWide_wIDArray_Response= 0x1D,
    UniverseVariableSvoURLResponse      = 0x1E,
    ChannelList_ExtraInfo               = 0x1F,
    GenericChatMessage                  = 0x23,
    GenericChatFwdMessage               = 0x24,
    GenericChatSetFilterRequest         = 0x25,
    GenericChatSetFilterResponse        = 0x26,
    ExtendedSessionBeginRequest         = 0x27,
    TokenRequest                        = 0x28,
    GetServerTimeRequest                = 0x2A,
    GetServerTimeResponse               = 0x2B,
    VoteToBanPlayerRequest              = 0x2C,
    SetAutoChatHistoryRequest           = 0x2D,
    SetAutoChatHistoryResponse          = 0x2E,
    CreateGame                          = 0x2F,
    WorldReport                         = 0x30,
    ClearGameListFilter                 = 0x31,
    GetGameListFilterResponse           = 0x32,
    SetGameListFilter                   = 0x33,
    SetGameListFilterResponse           = 0x34,
    GameInfo                            = 0x35,
    GameInfoResponse                    = 0x36,
    GameList_ExtraInfo                  = 0x37,
    GameList_ExtraInfoResponse          = 0x38,
    AccountUpdateStats_OpenAccess       = 0x39,
    AccountUpdateStats_OpenAccessResponse = 0x3A,
    AddPlayerToClan_ByClanOfficer       = 0x3B,
    AddPlayerToClan_ByClanOfficerResponse = 0x3C,
    // PS3-era extensions
    TicketLogin                         = 0x58,
    TicketLoginResponse                 = 0x59,
    GenericChatMessage1                 = 0x73,
    GenericChatFwdMessage1              = 0x74,
    MediusTextFilter1                   = 0x75,
    MediusTextFilterResponse1           = 0x76,
    SetLocalizationParams1              = 0x7B,
    SetLobbyWorldFilter1                = 0x86,
    SetLobbyWorldFilterResponse1        = 0x87,
    SessionBegin1                       = 0x8B,
}

/// <summary>
/// Medius status/result codes. Ported from horizon-server RT.Common/Types.cs.
/// </summary>
public enum MediusCallbackStatus : int
{
    MediusBeginSessionFailed                    = -1000,
    MediusAccountAlreadyExists                  = -999,
    MediusAccountNotFound                       = -998,
    MediusAccountLoggedIn                       = -997,
    MediusEndSessionFailed                      = -996,
    MediusLoginFailed                           = -995,
    MediusRegistrationFailed                    = -994,
    MediusIncorrectLoginStep                    = -993,
    MediusAlreadyLeaderOfClan                   = -992,
    MediusWMError                               = -991,
    MediusNotClanLeader                         = -990,
    MediusPlayerNotPrivileged                   = -989,
    MediusDBError                               = -988,
    MediusDMEError                              = -987,
    MediusExceedsMaxWorlds                      = -986,
    MediusRequestDenied                         = -985,
    MediusSetGameListFilterFailed               = -984,
    MediusClearGameListFilterFailed             = -983,
    MediusGetGameListFilterFailed               = -982,
    MediusNumFiltersAtMax                       = -981,
    MediusFilterNotFound                        = -980,
    MediusInvalidRequestMsg                     = -979,
    MediusInvalidPassword                       = -978,
    MediusGameNotFound                          = -977,
    MediusChannelNotFound                       = -976,
    MediusGameNameExists                        = -975,
    MediusChannelNameExists                     = -974,
    MediusGameNameNotFound                      = -973,
    MediusPlayerBanned                          = -972,
    MediusClanNotFound                          = -971,
    MediusClanNameInUse                         = -970,
    MediusSessionKeyInvalid                     = -969,
    MediusTextStringInvalid                     = -968,
    MediusFilterFailed                          = -967,
    MediusFail                                  = -966,
    MediusFileInternalAccessError               = -965,
    MediusFileNoPermissions                     = -964,
    MediusFileDoesNotExist                      = -963,
    MediusFileAlreadyExists                     = -962,
    MediusFileInvalidFilename                   = -961,
    MediusFileQuotaExceeded                     = -960,
    MediusCacheFailure                          = -959,
    MediusDataAlreadyExists                     = -958,
    MediusDataDoesNotExist                      = -957,
    MediusMaxExceeded                           = -956,
    MediusKeyError                              = -955,
    MediusIncompatibleAppID                     = -954,
    MediusAccountBanned                         = -953,
    MediusMachineBanned                         = -952,
    MediusLeaderCannotLeaveClan                 = -951,
    MediusFeatureNotEnabled                     = -950,
    MediusDNASSignatureLoggedIn                 = -949,
    MediusWorldIsFull                           = -948,
    MediusNotClanMember                         = -947,
    MediusServerBusy                            = -946,
    MediusNumGameWorldsPerLobbyWorldExceeded    = -945,
    MediusAccountNotUCCompliant                 = -944,
    MediusPasswordNotUCCompliant                = -943,
    MediusGatewayError                          = -942,
    MediusTransactionCanceled                   = -941,
    MediusSessionFail                           = -940,
    MediusTokenAlreadyTaken                     = -939,
    MediusTokenDoesNotExist                     = -938,
    MediusSubscriptionAborted                   = -937,
    MediusSubscriptionInvalid                   = -936,
    MediusNotAMember                            = -935,
    MediusSuccess                               = 0,
    MediusNoResult                              = 1,
    MediusRequestAccepted                       = 2,
    MediusWorldCreatedSizeReduced               = 3,
    MediusPass                                  = 4,
}

/// <summary>
/// Account type: child account vs master account.
/// </summary>
public enum MediusAccountType : int
{
    MediusChildAccount  = 0,
    MediusMasterAccount = 1,
}

/// <summary>
/// Ladder ranking type: individual player or clan.
/// </summary>
public enum MediusLadderType : int
{
    MediusLadderTypePlayer = 0,
    MediusLadderTypeClan   = 1,
}

/// <summary>
/// Player online status in the Medius world.
/// </summary>
public enum MediusPlayerStatus : int
{
    MediusPlayerDisconnected      = 0,
    MediusPlayerInAuthWorld       = 1,
    MediusPlayerInChatWorld       = 2,
    MediusPlayerInGameWorld       = 3,
    MediusPlayerInOtherUniverse   = 4,
}

/// <summary>
/// Text encoding used for player names and messages.
/// </summary>
public enum MediusCharacterEncodingType : int
{
    MediusCharacterEncoding_NoUpdate    = 0,
    MediusCharacterEncoding_ISO8859_1   = 1,
    MediusCharacterEncoding_UTF8        = 2,
}

/// <summary>
/// Client's preferred display language.
/// </summary>
public enum MediusLanguageType : int
{
    MediusLanguage_NoUpdate     = 0,
    MediusLanguage_USEnglish    = 1,
    MediusLanguage_UKEnglish    = 2,
    MediusLanguage_Japanese     = 3,
    MediusLanguage_Korean       = 4,
    MediusLanguage_Italian      = 5,
    MediusLanguage_Spanish      = 6,
    MediusLanguage_German       = 7,
    MediusLanguage_French       = 8,
    MediusLanguage_Dutch        = 9,
    MediusLanguage_Portuguese   = 10,
    MediusLanguage_Chinese      = 11,
    MediusLanguage_Taiwanese    = 12,
    MediusLanguage_Finnish      = 13,
    MediusLanguage_Norwegian    = 14,
}

/// <summary>
/// Clan status.
/// </summary>
public enum MediusClanStatus : int
{
    ClanActive    = 0,
    ClanDisbanded = -1,
}

/// <summary>
/// Network connection type reported by the client.
/// </summary>
public enum MediusConnectionType : int
{
    Modem    = 0,
    Ethernet = 1,
    Wireless = 2,
}

/// <summary>
/// DNAS signature category (console ID, title ID, or disc ID).
/// </summary>
public enum MediusDnasCategory : int
{
    DnasConsoleID = 0,
    DnasTitleID   = 1,
    DnasDiskID    = 2,
}

/// <summary>
/// Field to use when searching for a player.
/// </summary>
public enum MediusPlayerSearchType : int
{
    PlayerAccountID   = 0,
    PlayerAccountName = 1,
}

/// <summary>
/// Binary message delivery scope.
/// </summary>
public enum MediusBinaryMessageType : int
{
    BroadcastBinaryMsg                       = 0,
    TargetBinaryMsg                          = 1,
    BroadcastBinaryMsgAcrossEntireUniverse   = 2,
}

/// <summary>
/// Bitmask of generic field levels used when creating or filtering game worlds.
/// </summary>
[Flags]
public enum MediusWorldGenericFieldLevelType : int
{
    MediusWorldGenericFieldLevel0    = 0,
    MediusWorldGenericFieldLevel1    = (1 << 0),
    MediusWorldGenericFieldLevel2    = (1 << 1),
    MediusWorldGenericFieldLevel3    = (1 << 2),
    MediusWorldGenericFieldLevel4    = (1 << 3),
    MediusWorldGenericFieldLevel12   = (1 << 4),
    MediusWorldGenericFieldLevel123  = (1 << 5),
    MediusWorldGenericFieldLevel1234 = (1 << 6),
    MediusWorldGenericFieldLevel23   = (1 << 7),
    MediusWorldGenericFieldLevel234  = (1 << 8),
    MediusWorldGenericFieldLevel34   = (1 << 9),
}

/// <summary>
/// World application type: game or chat lobby.
/// </summary>
public enum MediusApplicationType : int
{
    MediusAppTypeGame    = 0,
    LobbyChatChannel     = 1,
}

/// <summary>
/// Text filter operation mode.
/// </summary>
public enum MediusTextFilterType : int
{
    MediusTextFilterPassFail = 0,
    MediusTextFilterReplace  = 1,
}

/// <summary>
/// Sort order for ranked results.
/// </summary>
public enum MediusSortOrder : int
{
    MEDIUS_ASCENDING  = 0,
    MEDIUS_DESCENDING = 1,
}

/// <summary>
/// Response to a clan invitation.
/// </summary>
public enum MediusClanInvitationsResponseStatus : int
{
    ClanInvitationUndecided = 0,
    ClanInvitationAccept    = 1,
    ClanInvitationDecline   = 2,
    ClanInvitationRevoked   = 3,
}

/// <summary>
/// Type of policy document to retrieve.
/// </summary>
public enum MediusPolicyType : int
{
    Usage   = 0,
    Privacy = 1,
}

/// <summary>
/// User keep-alive action.
/// </summary>
public enum MediusUserAction : int
{
    KeepAlive        = 0,
    JoinedChatWorld  = 1,
    LeftGameWorld    = 2,
}

/// <summary>
/// Join mode for a game world.
/// </summary>
public enum MediusJoinType : int
{
    MediusJoinAsPlayer        = 0,
    MediusJoinAsSpectator     = 1,
    MediusJoinAsMassSpectator = 2,
}

/// <summary>
/// Client timezone, reported as signed offset in units of 100ths of an hour.
/// </summary>
public enum MediusTimeZone : int
{
    MediusTimeZone_IDLW   = -1200,
    MediusTimeZone_HST    = -1000,
    MediusTimeZone_AKST   = -900,
    MediusTimeZone_AKDT   = -800,
    MediusTimeZone_PST    = -801,
    MediusTimeZone_PDT    = -700,
    MediusTimeZone_MST    = -701,
    MediusTimeZone_MDT    = -600,
    MediusTimeZone_CST    = -601,
    MediusTimeZone_CDT    = -500,
    MediusTimeZone_EST    = -501,
    MediusTimeZone_EDT    = -400,
    MediusTimeZone_AST    = -401,
    MediusTimeZone_NST    = -350,
    MediusTimeZone_ADT    = -300,
    MediusTimeZone_NDT    = -250,
    MediusTimeZone_WAT    = -100,
    MediusTimeZone_GMT    = 0,
    MediusTimeZone_UTC    = 1,
    MediusTimeZone_WET    = 2,
    MediusTimeZone_BST    = 100,
    MediusTimeZone_IRISHST= 101,
    MediusTimeZone_WEST   = 102,
    MediusTimeZone_CET    = 103,
    MediusTimeZone_CEST   = 200,
    MediusTimeZone_SWEDISHST = 201,
    MediusTimeZone_FST    = 202,
    MediusTimeZone_CAT    = 203,
    MediusTimeZone_SAST   = 204,
    MediusTimeZone_EET    = 205,
    MediusTimeZone_ISRAELST = 206,
    MediusTimeZone_EEST   = 300,
    MediusTimeZone_BT     = 301,
    MediusTimeZone_MSK    = 302,
    MediusTimeZone_IRANST = 350,
    MediusTimeZone_MSD    = 400,
    MediusTimeZone_INDIANST = 550,
    MediusTimeZone_JT     = 750,
    MediusTimeZone_HKT    = 800,
    MediusTimeZone_CCT    = 801,
    MediusTimeZone_AWST   = 802,
    MediusTimeZone_MT     = 850,
    MediusTimeZone_KST    = 900,
    MediusTimeZone_JST    = 901,
    MediusTimeZone_ACST   = 950,
    MediusTimeZone_AEST   = 1000,
    MediusTimeZone_GST    = 1001,
    MediusTimeZone_ACDT   = 1050,
    MediusTimeZone_AEDT   = 1100,
    MediusTimeZone_SST    = 1101,
    MediusTimeZone_NZST   = 1200,
    MediusTimeZone_IDLE   = 1201,
    MediusTimeZone_NZDT   = 1300,
}

/// <summary>
/// Game networking topology type.
/// </summary>
public enum MediusGameHostType : int
{
    MediusGameHostClientServer         = 0,
    MediusGameHostIntegratedServer     = 1,
    MediusGameHostPeerToPeer           = 2,
    MediusGameHostLANPlay              = 3,
    MediusGameHostClientServerAuxUDP   = 4,
}

/// <summary>
/// Bitmask of special attributes for a game world.
/// </summary>
[Flags]
public enum MediusWorldAttributesType : int
{
    GAME_WORLD_NONE              = 0,
    GAME_WORLD_ALLOW_REBROADCAST = (1 << 0),
    GAME_WORLD_ALLOW_SPECTATOR   = (1 << 1),
    GAME_WORLD_INTERNAL          = (1 << 2),
}

/// <summary>
/// Chat message delivery scope.
/// </summary>
public enum MediusChatMessageType : int
{
    Broadcast                        = 0,
    Whisper                          = 1,
    BroadcastAcrossEntireUniverse    = 2,
    MediusClanChatType               = 3,
    MediusBuddyChatType              = 4,
}

/// <summary>
/// Game world lifecycle status.
/// </summary>
public enum MediusWorldStatus : int
{
    WorldInactive               = 0,
    WorldStaging                = 1,
    WorldActive                 = 2,
    WorldClosed                 = 3,
    WorldPendingCreation        = 4,
    WorldPendingConnectToGame   = 5,
}

/// <summary>
/// Game list filter field selector.
/// </summary>
public enum MediusGameListFilterField : int
{
    MEDIUS_FILTER_PLAYER_COUNT      = 1,
    MEDIUS_FILTER_MIN_PLAYERS       = 2,
    MEDIUS_FILTER_MAX_PLAYERS       = 3,
    MEDIUS_FILTER_GAME_LEVEL        = 4,
    MEDIUS_FILTER_PLAYER_SKILL_LEVEL = 5,
    MEDIUS_FILTER_RULES_SET         = 6,
    MEDIUS_FILTER_GENERIC_FIELD_1   = 7,
    MEDIUS_FILTER_GENERIC_FIELD_2   = 8,
    MEDIUS_FILTER_GENERIC_FIELD_3   = 9,
    MEDIUS_FILTER_LOBBY_WORLDID     = 10,
    MEDIUS_FILTER_GENERIC_FIELD_4   = 11,
    MEDIUS_FILTER_GENERIC_FIELD_5   = 12,
    MEDIUS_FILTER_GENERIC_FIELD_6   = 13,
    MEDIUS_FILTER_GENERIC_FIELD_7   = 14,
    MEDIUS_FILTER_GENERIC_FIELD_8   = 15,
}

/// <summary>
/// World security access level.
/// </summary>
[Flags]
public enum MediusWorldSecurityLevelType : int
{
    WORLD_SECURITY_NONE           = 0,
    WORLD_SECURITY_PLAYER_PASSWORD = (1 << 0),
    WORLD_SECURITY_MODERATOR      = (1 << 1),
}

/// <summary>
/// Bitmask of packet receive filter flags for DME clients.
/// Controls which incoming packet types a client will receive.
/// </summary>
[Flags]
public enum RT_RECV_FLAG : byte
{
    RECV_SINGLE       = (1 << 0),   // receive unicast packets
    RECV_LIST         = (1 << 1),   // receive multicast list packets
    RECV_BROADCAST    = (1 << 2),   // receive broadcast packets
    RECV_NOTIFICATION = (1 << 3),   // receive join/leave notifications
}

/// <summary>
/// MGCL (Medius Game Collection Layer) event types, reported by DME to MLS.
/// </summary>
public enum MGCL_EVENT_TYPE : int
{
    MGCL_EVENT_CLIENT_CONNECT     = 0,
    MGCL_EVENT_CLIENT_DISCONNECT  = 1,
}

/// <summary>
/// MGCL error/result codes returned in server-to-server responses.
/// </summary>
public enum MGCL_ERROR_CODE : int
{
    MGCL_SUCCESS                                       = 0,
    MGCL_CONNECTION_ERROR                              = -1,
    MGCL_CONNECTION_FAILED                             = -2,
    MGCL_DISCONNECT_FAILED                             = -3,
    MGCL_NOT_CONNECTED                                 = -4,
    MGCL_SEND_FAILED                                   = -5,
    MGCL_INITIALIZATION_FAILED                         = -6,
    MGCL_SHUTDOWN_ERROR                                = -7,
    MGCL_NETWORK_ERROR                                 = -8,
    MGCL_AUTHENTICATION_FAILED                         = -9,
    MGCL_SESSIONBEGIN_FAILED                           = -10,
    MGCL_SESSIONEND_FAILED                             = -11,
    MGCL_UNSUCCESSFUL                                  = -12,
    MGCL_INVALID_ARG                                   = -13,
    MGCL_NATRESOLVE_FAILED                             = -14,
    MGCL_GAME_NAME_EXISTS                              = -15,
    MGCL_WORLDID_INUSE                                 = -16,
    MGCL_DME_ERROR                                     = -17,
    MGCL_CALL_MGCL_CLOSE_BEFORE_REINITIALIZING         = -18,
    MGCL_NUM_GAME_WORLDS_PER_LOBBY_WORLD_EXCEEDED      = -19,
}

/// <summary>
/// Trust level classification for MGCL server connections.
/// </summary>
public enum MGCL_TRUST_LEVEL : int
{
    MGCL_TRUSTED     = 0,
    MGCL_NOT_TRUSTED = 1,
}

/// <summary>
/// Game hosting topology as reported in MGCL.
/// </summary>
public enum MGCL_GAME_HOST_TYPE : int
{
    MGCLGameHostClientServer         = 0,
    MGCLGameHostIntegratedServer     = 1,
    MGCLGameHostPeerToPeer           = 2,
    MGCLGameHostLANPlay              = 3,
    MGCLGameHostClientServerAuxUDP   = 4,
}

/// <summary>
/// DME server-side cheat/integrity query types sent to the client.
/// </summary>
public enum CheatQueryType : byte
{
    DME_SERVER_CHEAT_QUERY_RAW_MEMORY            = 0,
    DME_SERVER_CHEAT_QUERY_SHA1_HASH             = 1,
    DME_SERVER_CHEAT_QUERY_MD5_HASH              = 2,
    DME_SERVER_CHEAT_QUERY_ACTIVE_THREAD_CNT     = 3,
    DME_SERVER_CHEAT_QUERY_REMENANT_THREAD_CNT   = 4,
    DME_SERVER_CHEAT_QUERY_SALTY_SHA1_HASH       = 5,
    DME_SERVER_CHEAT_QUERY_SALTY_MD5_HASH        = 6,
    DME_SERVER_CHEAT_QUERY_4BYTE_POKE_ADDRESS    = 8,
    DME_SERVER_CHEAT_QUERY_NO_OP_FUNC_ADDRESS    = 9,
    DME_SERVER_CHEAT_QUERY_INTERRUPT_CNT         = 10,
    DME_SERVER_CHEAT_QUERY_THREAD_INFO           = 11,
    DME_SERVER_CHEAT_QUERY_STRING_EXISTS         = 12,
    DME_SERVER_CHEAT_QUERY_IOP_RAW_MEMORY        = 13,
    DME_SERVER_CHEAT_QUERY_IOP_SHA1_HASH         = 14,
    DME_SERVER_CHEAT_QUERY_IOP_MD5_HASH          = 15,
    DME_SERVER_CHEAT_QUERY_IOP_SALTY_SHA1_HASH   = 16,
    DME_SERVER_CHEAT_QUERY_IOP_SALTY_MD5_HASH    = 17,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_RAW           = 18,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_SHA1          = 19,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_MD5           = 20,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_SALTY_SHA1    = 21,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_SALTY_MD5     = 22,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_CNT           = 23,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_TEXT_ADDR     = 24,
    DME_SERVER_CHEAT_QUERY_IOP_MOD_TEXT_SIZE     = 25,
    DME_SERVER_CHEAT_QUERY_IOP_THREAD_CNT        = 26,
    DME_SERVER_CHEAT_QUERY_IOP_MEM_FREE          = 27,
    DME_SERVER_CHEAT_QUERY_IOP_MEM_USED          = 28,
}

/// <summary>
/// Per-client network connection state in the DME session.
/// </summary>
public enum NetClientStatus : byte
{
    ClientStatusNone                 = 0,
    ClientStatusNotConnected         = 1,
    ClientStatusConnected            = 2,
    ClientStatusJoining              = 3,
    ClientStatusJoined               = 4,
    ClientStatusJoinedSessionMaster  = 5,
}

/// <summary>
/// Universe variable information filter flags, controlling which
/// fields are returned in GetUniverse_ExtraInfo responses.
/// </summary>
[Flags]
public enum MediusUniverseVariableInformationInfoFilter : uint
{
    INFO_UNIVERSES   = (1u << 0),
    INFO_NEWS        = (1u << 1),
    INFO_ID          = (1u << 2),
    INFO_NAME        = (1u << 3),
    INFO_DNS         = (1u << 4),
    INFO_DESCRIPTION = (1u << 5),
    INFO_STATUS      = (1u << 6),
    INFO_BILLING     = (1u << 7),
    INFO_EXTRAINFO   = (1u << 8),
    INFO_SVO_URL     = (1u << 9),
}

/// <summary>
/// Clan vs-clan challenge status.
/// </summary>
public enum MediusClanChallengeStatus : int
{
    ClanChallengeRequest   = 0,
    ClanChallengeAccepted  = 1,
    ClanChallengeRevoked   = 2,
    ClanChallengeRefused   = 3,
    ClanChallengeConfirmed = 4,
}

/// <summary>
/// Clan message read/modify/delete status.
/// </summary>
public enum MediusClanMessageStatus : int
{
    ClanMessageUnread    = 0,
    ClanMessageModified  = 1,
    ClanMessageDeleted   = 2,
    ClanMessageRead      = 3,
}

/// <summary>
/// Token action type for the token messaging system.
/// </summary>
public enum MediusTokenActionType : int
{
    MediusInvalidTokenAction = 0,
    MediusAddToken           = 1,
    MediusUpdateToken        = 2,
    MediusRemoveToken        = 3,
}

/// <summary>
/// Token category for the token messaging system.
/// </summary>
public enum MediusTokenCategoryType : int
{
    MediusInvalidToken   = 0,
    MediusGenericToken1  = 1,
    MediusGenericToken2  = 2,
    MediusGenericToken3  = 3,
    MediusAccountToken   = 4,
    MediusClanToken      = 5,
}

/// <summary>
/// File transfer progress stage.
/// </summary>
public enum MediusFileXferStatus : int
{
    Error   = 0,
    Initial = 1,
    Mid     = 2,
    End     = 3,
}

/// <summary>
/// DME application messages (MessageClassDME) on a game connection: what the DME server and the
/// game's DME library exchange inside RT_MSG_*_APP_* records. These are not the MGCL ids in
/// <see cref="MediusDmeMessageIds"/>, which reuse class 0 on lobby connections. Object
/// update/create/destroy layouts come from the game's class table (Mods/SOCOM2/packets/objects.json,
/// dme_objects.py); application messages (class 2) are listed in Mods/SOCOM2/packets/packets.json.
/// </summary>
public enum DmeAppMessageId : byte
{
    /// <summary>Server → client after connect: [Version:16] ("1.22.0140" on retail).</summary>
    ServerVersion = 0x00,
    /// <summary>TimeOfSend:u32 | PingInstance:u8 | RequestEcho:u8 | pad2.</summary>
    Ping          = 0x01,
    /// <summary>[type:1][n:1][objid:u16] then n × [field index:1][value].</summary>
    ObjectUpdate  = 0x03,
    /// <summary>[owner:1][type:1][00 00][u32 2][objid:u32][stamp:u32][u32 0][class name:16][all fields].</summary>
    ObjectCreate  = 0x04,
    /// <summary>Ends a packed batch of object messages.</summary>
    EndOfBatch    = 0x05,
    /// <summary>[objid:u16].</summary>
    ObjectDestroy = 0x0A,
}

/// <summary>
/// DME server-to-server MGCL message type IDs (MessageClassDME).
/// </summary>
public enum MediusDmeMessageIds : byte
{
    ServerReport                          = 0x00,
    ServerAuthenticationRequest           = 0x01,
    ServerAuthenticationResponse          = 0x02,
    ServerSessionBeginRequest             = 0x03,
    ServerSessionBeginResponse            = 0x04,
    ServerSessionEndRequest               = 0x05,
    ServerSessionEndResponse              = 0x06,
    ServerCreateGameRequest               = 0x07,
    ServerCreateGameResponse              = 0x08,
    ServerJoinGameRequest                 = 0x09,
    ServerJoinGameResponse                = 0x0A,
    ServerEndGameRequest                  = 0x0B,
    ServerEndGameResponse                 = 0x0C,
    ServerWorldStatusRequest              = 0x0D,
    ServerWorldStatusResponse             = 0x0E,
    ServerCreateGameOnMeRequest           = 0x1F,
    ServerCreateGameOnMeResponse          = 0x10,
    ServerEndGameOnMeRequest              = 0x11,
    ServerEndGameOnMeResponse             = 0x12,
    ServerMoveGameWorldOnMeRequest        = 0x14,
    ServerMoveGameWorldOnMeResponse       = 0x15,
    ServerSetAttributesRequest            = 0x16,
    ServerSetAttributesResponse           = 0x17,
    ServerCreateGameWithAttributesRequest = 0x18,
    ServerCreateGameWithAttributesResponse= 0x19,
    ServerConnectGamesRequest             = 0x1A,
    ServerConnectGamesResponse            = 0x1B,
    ServerConnectNotification             = 0x1C,
    ServerDisconnectPlayerRequest         = 0x1E,
    ServerWorldReportOnMe                 = 0x20,
}
